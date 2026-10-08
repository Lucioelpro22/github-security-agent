"""Official Gradle locking shapes and adversarial offline inventory boundaries."""

import pytest

from github_security_agent import dependency_audit as audit


def write_lock(tmp_path, text, name="gradle.lockfile"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_gradle_generated_modern_inventory(tmp_path):
    write_lock(
        tmp_path,
        "# This is a Gradle generated file for dependency locking.\n"
        "org.springframework:spring-core:5.0.5.RELEASE=compileClasspath, runtimeClasspath\n"
        "com.google.guava:guava:28.1-jre=runtimeClasspath\n"
        "empty=annotationProcessor\n",
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert report.manifests_scanned == 1
    assert {(d.name, d.version, d.ecosystem, d.source_kind) for d in report.dependencies} == {
        ("org.springframework:spring-core", "5.0.5.RELEASE", "Maven", "unknown"),
        ("com.google.guava:guava", "28.1-jre", "Maven", "unknown"),
    }


@pytest.mark.parametrize("name", ["gradle.lockfile", "buildscript-gradle.lockfile"])
def test_gradle_empty_modern_lock(tmp_path, name):
    write_lock(tmp_path, "# generated\nempty=\n", name)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert report.dependencies == ()


def test_gradle_legacy_configuration_lock(tmp_path):
    write_lock(
        tmp_path,
        "# generated\norg.example:library:1.2.3\n",
        "gradle/dependency-locks/runtimeClasspath.lockfile",
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert [d.name for d in report.dependencies] == ["org.example:library"]


@pytest.mark.parametrize("query_osv", [False, True])
def test_gradle_private_registry_identity_never_sent_to_osv(tmp_path, monkeypatch, query_osv):
    write_lock(tmp_path, "private.company:secret-package:1.2.3=runtimeClasspath\nempty=\n")
    monkeypatch.setattr(
        audit, "_post_osv_batch", lambda _: pytest.fail("Gradle identity sent to OSV")
    )
    report = audit.audit_dependencies(tmp_path, query_osv=query_osv)
    assert len(report.dependencies) == 1
    assert report.advisory_lookup == ("incomplete" if query_osv else "not_requested")


@pytest.mark.parametrize(
    "body",
    [
        "",
        "# only comments\n",
        "org.example:library:1.0=runtimeClasspath\n",
        "empty=\nempty=\n",
        "empty=runtimeClasspath\norg.example:library:1.0=runtimeClasspath\n",
        "org.example:library:1.0=runtimeClasspath,runtimeClasspath\nempty=\n",
        "org.example:library:1.0=runtimeClasspath\norg.example:library:1.0=runtimeClasspath\nempty=\n",
        "org.example:library:1.0=runtimeClasspath\norg.example:library:2.0=runtimeClasspath\nempty=\n",
        "org.example:library:1.0=\nempty=\n",
        "org.example:library:1.0=runtimeClasspath,\nempty=\n",
        "org.example:library:1.0=runtimeClasspath=other\nempty=\n",
        "org.example:library:1.0:classifier=runtimeClasspath\nempty=\n",
        "org.example:library=runtimeClasspath\nempty=\n",
    ],
)
def test_gradle_malformed_or_ambiguous_graph_incomplete(tmp_path, body):
    write_lock(tmp_path, body)
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


@pytest.mark.parametrize(
    "version",
    [
        "1.+",
        "latest.release",
        "latest.integration",
        "[1,2)",
        "1.0+secret",
        "https://canary-password@example.test",
        "1.0\x00canary-password",
    ],
)
def test_gradle_unresolved_or_unsafe_versions_not_disclosed(tmp_path, version):
    write_lock(tmp_path, f"org.example:library:{version}=runtimeClasspath\nempty=\n")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()
    assert "canary-password" not in audit.report_json(report) + audit.report_markdown(report)


def test_gradle_disjoint_configuration_versions(tmp_path):
    write_lock(
        tmp_path,
        "org.example:library:1.0=compileClasspath\norg.example:library:2.0=runtimeClasspath\nempty=\n",
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert {d.version for d in report.dependencies} == {"1.0", "2.0"}


@pytest.mark.parametrize("limit,status,count", [(1, "incomplete", 1), (2, "complete", 2)])
def test_gradle_dependency_budget_exact_boundary(tmp_path, monkeypatch, limit, status, count):
    write_lock(
        tmp_path,
        "org.example:first:1.0=runtimeClasspath\norg.example:second:1.0=runtimeClasspath\nempty=\n",
    )
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", limit)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == status
    assert len(report.dependencies) == count


def test_gradle_size_limit_fails_closed(tmp_path, monkeypatch):
    write_lock(tmp_path, "org.example:library:1.0=runtimeClasspath\nempty=\n")
    monkeypatch.setattr(audit, "MAX_LOCKFILE_BYTES", 16)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_gradle_invalid_utf8_not_disclosed(tmp_path):
    (tmp_path / "gradle.lockfile").write_bytes(b"\xffcanary-password")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert "canary-password" not in audit.report_json(report)


@pytest.mark.parametrize("manifest", ["build.gradle", "build.gradle.kts"])
def test_gradle_manifest_without_lock_unknown(tmp_path, manifest):
    (tmp_path / manifest).write_text("throw new RuntimeException('must never execute')")
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


@pytest.mark.parametrize("manifest", ["build.gradle", "build.gradle.kts"])
def test_gradle_modern_companion_covers_manifest(tmp_path, manifest):
    (tmp_path / manifest).write_text("invalid executable content")
    write_lock(tmp_path, "org.example:library:1.0=runtimeClasspath\nempty=\n")
    assert audit.audit_dependencies(tmp_path).status == "complete"


def test_gradle_buildscript_lock_does_not_cover_project_manifest(tmp_path):
    (tmp_path / "build.gradle").write_text("invalid executable content")
    write_lock(
        tmp_path, "org.example:plugin:1.0=classpath\nempty=\n", "buildscript-gradle.lockfile"
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert len(report.dependencies) == 1


def test_gradle_legacy_inventory_does_not_prove_manifest_coverage(tmp_path):
    (tmp_path / "build.gradle").write_text("invalid executable content")
    write_lock(
        tmp_path, "org.example:library:1.0\n", "gradle/dependency-locks/runtimeClasspath.lockfile"
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert len(report.dependencies) == 1


def test_gradle_external_symlink_cannot_cover_manifest(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.lockfile"
    outside.write_text("private.company:secret:1.0=runtimeClasspath\nempty=\n")
    (tmp_path / "build.gradle").write_text("invalid executable content")
    (tmp_path / "gradle.lockfile").symlink_to(outside)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_gradle_unrelated_legacy_filename_not_inventoried(tmp_path):
    write_lock(tmp_path, "org.example:library:1.0\n", "runtimeClasspath.lockfile")
    report = audit.audit_dependencies(tmp_path)
    assert report.dependencies == ()
    assert report.manifests_scanned == 0


def test_gradle_legacy_duplicate_coordinates_incomplete(tmp_path):
    write_lock(
        tmp_path,
        "org.example:library:1.0\norg.example:library:1.0\n",
        "gradle/dependency-locks/runtimeClasspath.lockfile",
    )
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


def test_gradle_configuration_edge_budget(tmp_path, monkeypatch):
    configurations = ",".join(f"configuration{i}" for i in range(11))
    write_lock(tmp_path, f"org.example:library:1.0={configurations}\nempty=\n")
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", 1)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_gradle_nested_modern_lock_cannot_cover_parent_manifest(tmp_path):
    (tmp_path / "build.gradle.kts").write_text("invalid executable content")
    write_lock(
        tmp_path, "org.example:library:1.0=runtimeClasspath\nempty=\n", "child/gradle.lockfile"
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert len(report.dependencies) == 1


def test_gradle_custom_lock_location_not_executed_or_inferred(tmp_path):
    (tmp_path / "build.gradle.kts").write_text(
        'dependencyLocking { lockFile = file("custom.lock") }'
    )
    write_lock(tmp_path, "private.company:secret:1.0=runtimeClasspath\nempty=\n", "custom.lock")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_gradle_modern_and_legacy_coexistence_inventory_incomplete(tmp_path):
    write_lock(tmp_path, "org.example:modern:1.0=compileClasspath\nempty=\n")
    write_lock(
        tmp_path,
        "org.example:legacy:2.0\n",
        "gradle/dependency-locks/runtimeClasspath.lockfile",
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert {d.name for d in report.dependencies} == {"org.example:modern", "org.example:legacy"}
