"""Swift lock inventory stays bounded, local, and independent of package evaluation."""

import json

import pytest

from github_security_agent import dependency_audit as audit


def pin(identity="example", **state):
    return {
        "identity": identity,
        "kind": "remoteSourceControl",
        "location": "https://private.example/secret-repository",
        "state": state or {"version": "1.2.3", "revision": "a" * 40},
    }


def write_lock(tmp_path, pins=None, version=2, name="Package.resolved", **extra):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": version, "pins": [pin()] if pins is None else pins, **extra}),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("revision", [None, "a" * 40, "b" * 64])
def test_swift_exact_git_release_versions(tmp_path, version, revision):
    write_lock(tmp_path, [pin(version="1.2.3", revision=revision)], version=version)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert [(d.name, d.version, d.ecosystem, d.source_kind) for d in report.dependencies] == [
        ("example", "1.2.3", "Swift", "unknown")
    ]
    assert "secret-repository" not in audit.report_json(report) + audit.report_markdown(report)


def test_swift_registry_empty_location_version_only(tmp_path):
    record = pin(version="2.0.0")
    record.update(kind="registry", location="")
    write_lock(tmp_path, [record], version=3, originHash="a" * 64)
    assert audit.audit_dependencies(tmp_path).status == "complete"


@pytest.mark.parametrize("query_osv", [False, True])
def test_swift_unknown_origin_never_queries_osv(tmp_path, monkeypatch, query_osv):
    write_lock(tmp_path)
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("Swift leaked to OSV"))
    report = audit.audit_dependencies(tmp_path, query_osv=query_osv)
    assert len(report.dependencies) == 1
    assert report.advisory_lookup == ("incomplete" if query_osv else "not_requested")
    assert report.status == ("incomplete" if query_osv else "complete")


@pytest.mark.parametrize("version", [1, 4, True, "2", None])
def test_swift_unsupported_schema_incomplete(tmp_path, version):
    write_lock(tmp_path, version=version)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize(
    "state",
    [
        {"version": "1.2.3", "branch": "main"},
        {"branch": "main", "revision": "a" * 40},
        {"revision": "a" * 40},
        {"version": "1.2"},
        {"version": "1.0.0-01"},
        {"version": "1.2.3", "revision": "not-a-hash"},
        {"version": 123},
        {"version": "1.2.3", "branch": ""},
        {"version": "1.2.3", "branch": "main\n"},
    ],
)
def test_swift_ambiguous_or_unresolved_pin_omitted(tmp_path, state):
    write_lock(tmp_path, [pin(**state)])
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize("record", [None, [], {}, {"identity": "example"}])
def test_swift_malformed_record_incomplete(tmp_path, record):
    write_lock(tmp_path, [record])
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


@pytest.mark.parametrize(
    "field,value", [("kind", "future"), ("location", 123), ("location", ""), ("state", [])]
)
def test_swift_malformed_fields_incomplete(tmp_path, field, value):
    record = pin()
    record[field] = value
    write_lock(tmp_path, [record])
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_swift_identity_case_collision_incomplete(tmp_path):
    write_lock(tmp_path, [pin("example"), pin("Example")])
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert len(report.dependencies) == 1


@pytest.mark.parametrize(
    "body",
    [
        '{"version":2,"version":3,"pins":[]}',
        '{"version":2,"pins":[{"identity":"a","identity":"b"}]}',
        '{"version":2,"pins":[{"state":{"version":"1.2.3","version":"2.0.0"}}]}',
        '{"version":2,"pins":{}}',
        "[]",
        "{",
    ],
)
def test_swift_invalid_or_duplicate_json_incomplete(tmp_path, body):
    (tmp_path / "Package.resolved").write_text(body)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_swift_unknown_fields_preserve_pin_but_mark_incomplete(tmp_path):
    write_lock(tmp_path, future=True)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert len(report.dependencies) == 1


@pytest.mark.parametrize("limit,status,count", [(1, "incomplete", 1), (2, "complete", 2)])
def test_swift_package_budget_boundary(tmp_path, monkeypatch, limit, status, count):
    write_lock(tmp_path, [pin("first"), pin("second")])
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", limit)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == status
    assert len(report.dependencies) == count


def test_swift_size_limit_incomplete(tmp_path, monkeypatch):
    write_lock(tmp_path)
    monkeypatch.setattr(audit, "MAX_LOCKFILE_BYTES", 16)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_swift_deep_json_fails_closed(tmp_path):
    (tmp_path / "Package.resolved").write_text("[" * 2000 + "0" + "]" * 2000)
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


def test_swift_manifest_missing_companion_incomplete(tmp_path):
    (tmp_path / "Package.swift").write_text('fatalError("never execute")')
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_swift_companion_is_inventory_only_no_execution(tmp_path):
    marker = tmp_path / "executed"
    (tmp_path / "Package.swift").write_text(f"import os; os.mkdir({str(marker)!r})")
    write_lock(tmp_path)
    assert audit.audit_dependencies(tmp_path).status == "complete"
    assert not marker.exists()


def test_swift_nested_xcode_filename_discovered(tmp_path):
    name = "Example.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"
    write_lock(tmp_path, name=name)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert report.dependencies[0].manifest == name


def test_swift_nested_lock_does_not_cover_root_manifest(tmp_path):
    (tmp_path / "Package.swift").write_text('fatalError("never execute")')
    write_lock(tmp_path, name="nested/Package.resolved")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert len(report.dependencies) == 1


def test_swift_symlink_lock_cannot_cover_manifest(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.json"
    outside.write_text(json.dumps({"version": 2, "pins": [pin()]}))
    (tmp_path / "Package.swift").write_text('fatalError("never execute")')
    (tmp_path / "Package.resolved").symlink_to(outside)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()
