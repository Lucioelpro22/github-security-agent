"""Dart lock inventory is bounded, offline, and does not evaluate manifests."""

import pytest
import yaml

from github_security_agent import dependency_audit as audit


def package(source="hosted", description=None, version="1.2.3"):
    return {
        "dependency": "direct main",
        "description": (
            {"name": "example", "url": "https://private.example/secret-location"}
            if description is None
            else description
        ),
        "source": source,
        "version": version,
    }


def write_lock(tmp_path, packages=None, name="pubspec.lock", **extra):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(
            {"packages": {"example": package()} if packages is None else packages, **extra}
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(
    "source,description",
    [
        ("hosted", "example"),
        ("hosted", {"name": "example", "url": "https://pub.dev"}),
        ("hosted", {"name": "example", "url": "https://pub.dev", "sha256": "a" * 64}),
        (
            "git",
            {
                "url": "https://private.example/secret-location",
                "ref": "main",
                "resolved-ref": "a" * 40,
                "path": ".",
            },
        ),
        ("path", {"path": "../secret-location", "relative": True}),
        ("sdk", "flutter"),
    ],
)
def test_dart_sources_inventory_without_location_disclosure(tmp_path, source, description):
    write_lock(tmp_path, {"example": package(source, description)}, sdks={"dart": ">=3.0.0 <4.0.0"})
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    source_kind = {"hosted": "registry-other", "git": "git", "path": "directory", "sdk": "unknown"}[
        source
    ]
    assert [(d.name, d.version, d.ecosystem, d.source_kind) for d in report.dependencies] == [
        ("example", "1.2.3", "Dart", source_kind)
    ]
    assert "secret-location" not in audit.report_json(report) + audit.report_markdown(report)


@pytest.mark.parametrize("query_osv", [False, True])
def test_dart_never_queries_osv_even_public_hosted(tmp_path, monkeypatch, query_osv):
    write_lock(
        tmp_path, {"example": package(description={"name": "example", "url": "https://pub.dev"})}
    )
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("Dart leaked to OSV"))
    report = audit.audit_dependencies(tmp_path, query_osv=query_osv)
    assert len(report.dependencies) == 1
    assert report.advisory_lookup == ("incomplete" if query_osv else "not_requested")
    assert report.status == ("incomplete" if query_osv else "complete")


@pytest.mark.parametrize("version", ["1.2.3", "0.0.0", "1.2.3-dev.2", "1.2.3+build.4"])
def test_dart_exact_release_versions(tmp_path, version):
    write_lock(tmp_path, {"example": package(version=version)})
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert report.dependencies[0].version == version


def test_dart_dependency_metadata_optional(tmp_path):
    record = package()
    del record["dependency"]
    write_lock(tmp_path, {"example": record})
    assert audit.audit_dependencies(tmp_path).status == "complete"


def test_dart_git_tag_pattern_inventory(tmp_path):
    write_lock(
        tmp_path,
        {
            "example": package(
                "git",
                {
                    "url": "https://private.example/secret-location",
                    "tag-pattern": "v{{version}}",
                    "resolved-ref": "a" * 40,
                    "path": ".",
                },
            )
        },
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert len(report.dependencies) == 1


@pytest.mark.parametrize("relative", ["true", "false", 0, 1, None])
def test_dart_path_relative_requires_yaml_bool(tmp_path, relative):
    write_lock(
        tmp_path, {"example": package("path", {"path": "../secret-location", "relative": relative})}
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize(
    "source,description",
    [
        ("future", "example"),
        ("hosted", "different"),
        ("hosted", {"name": "different", "url": "https://pub.dev"}),
        ("hosted", {"name": "example", "url": "https://pub.dev", "sha256": "not-a-hash"}),
        ("git", {"url": "https://private.example/secret-location", "resolved-ref": "not-a-hash"}),
        (
            "git",
            {
                "url": "https://private.example/secret-location",
                "ref": "main",
                "tag-pattern": "v{{version}}",
                "resolved-ref": "a" * 40,
            },
        ),
        ("path", {"path": "../secret-location"}),
        ("sdk", {}),
    ],
)
def test_dart_malformed_source_metadata_omitted_without_leak(tmp_path, source, description):
    write_lock(tmp_path, {"example": package(source, description)})
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()
    assert "secret-location" not in audit.report_json(report) + audit.report_markdown(report)


@pytest.mark.parametrize("name", ["Example", "with-dash", "../outside", "a" * 257])
def test_dart_invalid_names_omitted(tmp_path, name):
    write_lock(tmp_path, {name: package(description=name)})
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_dart_real_analyzer_leading_underscore_name(tmp_path):
    name = "_fe_analyzer_shared"
    write_lock(
        tmp_path,
        {name: package(description={"name": name, "url": "https://pub.dev"}, version="96.0.0")},
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert [(d.name, d.version) for d in report.dependencies] == [(name, "96.0.0")]


@pytest.mark.parametrize("level", ["root", "package"])
def test_dart_unknown_fields_mark_partial_inventory(tmp_path, level):
    record = package()
    extra = {}
    if level == "root":
        extra["future"] = True
    else:
        record["future"] = True
    write_lock(tmp_path, {"example": record}, **extra)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert len(report.dependencies) == 1


def test_dart_all_sources_excluded_from_osv(tmp_path, monkeypatch):
    write_lock(
        tmp_path,
        {
            "example": package(),
            "git_dep": package(
                "git", {"url": "https://private.example/repository", "resolved-ref": "a" * 40}
            ),
            "path_dep": package("path", {"path": "../outside", "relative": True}),
            "sdk_dep": package("sdk", "flutter"),
        },
    )
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("Dart leaked to OSV"))
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert len(report.dependencies) == 4
    assert report.status == "incomplete"
    assert report.advisory_lookup == "incomplete"


@pytest.mark.parametrize(
    "version", ["1.2", "^1.2.3", "01.2.3", "1.2.3-01", "any", 123, None, "1.2.3\n"]
)
def test_dart_invalid_release_omitted(tmp_path, version):
    write_lock(tmp_path, {"example": package(version=version)})
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize("record", [None, [], {}, {"source": "hosted"}])
def test_dart_malformed_package_incomplete(tmp_path, record):
    write_lock(tmp_path, {"example": record})
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize(
    "body",
    [
        "[]",
        "packages: []",
        "packages: null",
        "packages: {}\npackages: {}",
        "packages:\n  example: {}\n  example: {}",
        "packages: !!python/object:builtins.object {}",
        "packages: &pins {}",
        "packages: &pins {}\nsdks: *pins",
        "packages: {}\n---\npackages: {}",
        "packages: {",
        "packages: {example: {source: hosted, source: git}}",
    ],
)
def test_dart_invalid_yaml_fails_closed(tmp_path, body):
    (tmp_path / "pubspec.lock").write_text(body)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_dart_deep_yaml_fails_closed(tmp_path):
    (tmp_path / "pubspec.lock").write_text("packages: " + "[" * 2000 + "0" + "]" * 2000)
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


def test_dart_size_budget(tmp_path, monkeypatch):
    write_lock(tmp_path)
    monkeypatch.setattr(audit, "MAX_LOCKFILE_BYTES", 16)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize("limit,status,count", [(1, "incomplete", 1), (2, "complete", 2)])
def test_dart_package_budget(tmp_path, monkeypatch, limit, status, count):
    write_lock(tmp_path, {"example": package(), "other": package(description="other")})
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", limit)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == status
    assert len(report.dependencies) == count


def test_dart_manifest_missing_lock_incomplete(tmp_path):
    (tmp_path / "pubspec.yaml").write_text("name: example\ndependencies:\n  foo: any\n")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_dart_manifest_is_not_evaluated(tmp_path):
    marker = tmp_path / "executed"
    (tmp_path / "pubspec.yaml").write_text(f"!!python/object/apply:os.mkdir [{str(marker)!r}]")
    write_lock(tmp_path)
    assert audit.audit_dependencies(tmp_path).status == "complete"
    assert not marker.exists()


def test_dart_nested_lock_discovered(tmp_path):
    write_lock(tmp_path, name="mobile/pubspec.lock")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert report.dependencies[0].manifest == "mobile/pubspec.lock"


def test_dart_nested_lock_does_not_cover_root_manifest(tmp_path):
    (tmp_path / "pubspec.yaml").write_text("name: root\n")
    write_lock(tmp_path, name="nested/pubspec.lock")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert len(report.dependencies) == 1


def test_dart_symlink_lock_does_not_cover_manifest(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.lock"
    outside.write_text(yaml.safe_dump({"packages": {"example": package()}}))
    (tmp_path / "pubspec.yaml").write_text("name: example\n")
    (tmp_path / "pubspec.lock").symlink_to(outside)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()
