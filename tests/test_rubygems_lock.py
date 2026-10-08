"""Bundler-shaped fixtures exercise inventory and source privacy boundaries."""

import pytest

from github_security_agent import dependency_audit as audit


def lock(specs="    rack (3.1.0)\n", dependencies="  rack\n", remotes=None):
    remotes = ["https://rubygems.org/"] if remotes is None else remotes
    return (
        "GEM\n"
        + "".join(f"  remote: {remote}\n" for remote in remotes)
        + "  specs:\n"
        + specs
        + "\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n"
        + dependencies
        + "\nBUNDLED WITH\n   2.5.23\n"
    )


def write_lock(tmp_path, body):
    (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\n', encoding="utf-8")
    (tmp_path / "Gemfile.lock").write_text(body, encoding="utf-8")


def test_ruby_local_inventory_has_companion_and_never_queries(tmp_path, monkeypatch):
    write_lock(tmp_path, lock("    rack (3.1.0)\n      logger (>= 1.0)\n    logger (1.6.1)\n"))
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("default audit sent data"))
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert report.manifests_scanned == 1
    assert report.advisory_lookup == "not_requested"
    assert {(d.name, d.version, d.ecosystem, d.source_kind) for d in report.dependencies} == {
        ("rack", "3.1.0", "RubyGems", "registry-rubygems"),
        ("logger", "1.6.1", "RubyGems", "registry-rubygems"),
    }


def test_ruby_optin_queries_public_exact_and_prerelease_versions(tmp_path, monkeypatch):
    write_lock(tmp_path, lock("    rack (3.1.0.rc1)\n"))
    sent = []
    monkeypatch.setattr(
        audit, "_post_osv_batch", lambda batch: sent.extend(batch) or [[] for _ in batch]
    )
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "complete"
    assert [(d.name, d.version) for d in sent] == [("rack", "3.1.0.rc1")]


@pytest.mark.parametrize(
    "remotes",
    [
        ["https://packages.internal/"],
        ["https://rubygems.org.evil.example/"],
        ["https://rubygems.org@evil.example/"],
        ["https://username:private-password@rubygems.org/"],
        ["https://rubygems.org:444/"],
        ["http://rubygems.org/"],
        ["https://rubygems.org/?token=private-password"],
        ["https://rubygems.org/#private-password"],
        ["https://rubygems.org/private"],
        ["https://rubygems.org/", "https://packages.internal/"],
    ],
)
def test_ruby_untrusted_registry_never_queried_or_disclosed(tmp_path, monkeypatch, remotes):
    write_lock(tmp_path, lock(remotes=remotes))
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("private source queried"))
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert report.advisory_lookup == "incomplete"
    assert {(d.name, d.version) for d in report.dependencies} == {("rack", "3.1.0")}
    rendered = audit.report_json(report) + audit.report_markdown(report)
    assert "private-password" not in rendered
    assert "packages.internal" not in rendered


@pytest.mark.parametrize(
    "section,metadata,kind",
    [
        (
            "GIT",
            "  remote: https://username:private-password@example.com/team/rack.git\n  revision: 0123456789012345678901234567890123456789\n",
            "git",
        ),
        ("PATH", "  remote: ../private-password\n", "directory"),
    ],
)
def test_ruby_git_and_path_pinned_declarations_inventory_only(
    tmp_path, monkeypatch, section, metadata, kind
):
    body = f"{section}\n{metadata}  specs:\n    rack (3.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack!\n\nBUNDLED WITH\n   2.5.23\n"
    write_lock(tmp_path, body)
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("nonregistry queried"))
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert [(d.name, d.version, d.source_kind) for d in report.dependencies] == [
        ("rack", "3.1.0", kind)
    ]
    assert "private-password" not in audit.report_json(report)


def test_ruby_platform_version_retained_but_not_queried(tmp_path, monkeypatch):
    write_lock(tmp_path, lock("    nokogiri (1.16.2-x86_64-linux)\n", "  nokogiri\n"))
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("platform version queried"))
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert [(d.name, d.version) for d in report.dependencies] == [
        ("nokogiri", "1.16.2-x86_64-linux")
    ]


def test_ruby_unicode_digit_version_is_not_a_public_package_version(tmp_path, monkeypatch):
    write_lock(tmp_path, lock("    rack (\u0663.1.0)\n"))
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("invalid version queried"))
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize(
    "specs,dependencies",
    [
        ("    rack (3.1.0)\n      absent (>= 1.0)\n", "  rack\n"),
        ("    rack (3.1.0)\n", "  absent\n"),
        ("    rack (3.1.0)\n", "  rack!\n"),
    ],
)
def test_ruby_missing_or_source_pinned_references_are_incomplete(tmp_path, specs, dependencies):
    write_lock(tmp_path, lock(specs, dependencies))
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert [(d.name, d.version) for d in report.dependencies] == [("rack", "3.1.0")]


@pytest.mark.parametrize(
    "body",
    [
        lock() + "\nMYSTERY\n  unsupported\n",
        lock().replace("    rack (3.1.0)", "    rack (>= 3.1)"),
        lock().replace("    rack (3.1.0)", "    rack"),
        lock().replace("  specs:", "  unsupported: private-password\n  specs:"),
        lock().replace("    rack (3.1.0)", "    rack (3.1.0)\n    rack (4.0.0)"),
    ],
)
def test_ruby_unknown_or_conflicting_syntax_never_reports_complete(tmp_path, body):
    write_lock(tmp_path, body)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert "private-password" not in audit.report_json(report)


def test_ruby_dependency_cap_is_explicit(tmp_path, monkeypatch):
    write_lock(tmp_path, lock("    rack (3.1.0)\n    logger (1.6.1)\n"))
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", 1)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert len(report.dependencies) == 1


def test_ruby_invalid_utf8_is_safely_reported(tmp_path):
    (tmp_path / "Gemfile.lock").write_bytes(b"GEM\n\xffprivate-password")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()
    assert "private-password" not in audit.report_json(report)


@pytest.mark.parametrize("section", ["CONTENT ADDRESSES", "<<<<<<< HEAD"])
def test_ruby_unsupported_sections_and_conflict_markers_incomplete(tmp_path, section):
    write_lock(tmp_path, lock() + f"\n{section}\n  rack (3.1.0)\n")
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


def test_ruby_same_identity_across_path_and_public_is_not_queried(tmp_path, monkeypatch):
    body = "PATH\n  remote: ../local\n  specs:\n    rack (3.1.0)\n\n" + lock(
        dependencies="  rack!\n"
    )
    write_lock(tmp_path, body)
    monkeypatch.setattr(
        audit, "_post_osv_batch", lambda _: pytest.fail("ambiguous identity queried")
    )
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert report.advisory_lookup == "incomplete"


def test_ruby_checksum_metadata_does_not_add_bundler_dependency(tmp_path):
    body = lock().replace(
        "\nBUNDLED WITH",
        "\nCHECKSUMS\n  rack (3.1.0) sha256="
        + "a" * 64
        + "\n  bundler (2.5.23) sha256="
        + "b" * 64
        + "\n\nBUNDLED WITH",
    )
    write_lock(tmp_path, body)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert [d.name for d in report.dependencies] == ["rack"]


def test_ruby_duplicate_registry_remote_is_ambiguous(tmp_path, monkeypatch):
    write_lock(tmp_path, lock(remotes=["https://rubygems.org/", "https://rubygems.org/"]))
    monkeypatch.setattr(
        audit, "_post_osv_batch", lambda _: pytest.fail("duplicate sources queried")
    )
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert report.advisory_lookup == "incomplete"


def test_ruby_distinct_registry_blocks_have_ambiguous_package_provenance(tmp_path, monkeypatch):
    body = "GEM\n  remote: https://packages.internal/\n  specs:\n    internal (1.0.0)\n\n" + lock()
    write_lock(tmp_path, body)
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("split sources queried"))
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert {d.name for d in report.dependencies} == {"rack", "internal"}


def test_ruby_crlf_lock_is_supported(tmp_path):
    write_lock(tmp_path, lock().replace("\n", "\r\n"))
    assert audit.audit_dependencies(tmp_path).status == "complete"


@pytest.mark.parametrize("dependencies", ["  rack (evil)\n", "  rack\n  rack\n", "    rack\n"])
def test_ruby_invalid_direct_requirements_are_incomplete(tmp_path, dependencies):
    write_lock(tmp_path, lock(dependencies=dependencies))
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


def test_ruby_invalid_transitive_requirement_is_incomplete(tmp_path):
    write_lock(tmp_path, lock("    rack (3.1.0)\n      logger (evil)\n    logger (1.6.1)\n"))
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


def test_ruby_valid_multiple_requirement_operators_are_supported(tmp_path):
    write_lock(
        tmp_path,
        lock(
            "    rack (3.1.0)\n      logger (>= 1.0, < 2.0)\n    logger (1.6.1)\n",
            "  rack (~> 3.1)\n",
        ),
    )
    assert audit.audit_dependencies(tmp_path).status == "complete"


@pytest.mark.parametrize("version", ["https://canary-password@example.test/gem", "garbage"])
def test_ruby_invalid_spec_versions_never_disclosed(tmp_path, version):
    write_lock(tmp_path, lock(f"    rack ({version})\n"))
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()
    assert version not in audit.report_json(report) + audit.report_markdown(report)


def test_ruby_invalid_git_revision_is_incomplete(tmp_path):
    body = "GIT\n  remote: https://example.test/rack.git\n  revision: invalid-revision\n  specs:\n    rack (3.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack!\n\nBUNDLED WITH\n   2.5.23\n"
    write_lock(tmp_path, body)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert "invalid-revision" not in audit.report_json(report)


def test_ruby_capped_later_path_identity_never_queries_public_prefix(tmp_path, monkeypatch):
    body = lock() + "\nPATH\n  remote: ../private\n  specs:\n    rack (3.1.0)\n"
    write_lock(tmp_path, body)
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", 1)
    monkeypatch.setattr(
        audit, "_post_osv_batch", lambda _: pytest.fail("capped ambiguous source queried")
    )
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert all(d.source_kind != "registry-rubygems" for d in report.dependencies)


def test_ruby_malformed_source_metadata_never_queries(tmp_path, monkeypatch):
    write_lock(tmp_path, lock().replace("  specs:", "  arbitrary: canary-password\n  specs:"))
    monkeypatch.setattr(
        audit, "_post_osv_batch", lambda _: pytest.fail("malformed registry source queried")
    )
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert "canary-password" not in audit.report_json(report)


def test_ruby_remote_after_specs_never_queries(tmp_path, monkeypatch):
    write_lock(
        tmp_path,
        lock().replace(
            "    rack (3.1.0)", "    rack (3.1.0)\n  remote: https://private-password@example.test/"
        ),
    )
    monkeypatch.setattr(
        audit, "_post_osv_batch", lambda _: pytest.fail("malformed source order queried")
    )
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert "private-password" not in audit.report_json(report)


def test_ruby_invalid_git_revision_demotes_other_public_source(tmp_path, monkeypatch):
    body = (
        "GIT\n  remote: https://example.test/local.git\n  revision: malformed\n  specs:\n    local (1.0.0)\n\n"
        + lock()
    )
    write_lock(tmp_path, body)
    monkeypatch.setattr(
        audit, "_post_osv_batch", lambda _: pytest.fail("structurally incomplete lock queried")
    )
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert all(d.source_kind != "registry-rubygems" for d in report.dependencies)
