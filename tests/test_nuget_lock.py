"""NuGet-generated lock shapes and adversarial provenance/graph boundaries."""

import json

import pytest

from github_security_agent import dependency_audit as audit


HASH = "a" * 86 + "=="


def package(kind="Direct", version="1.2.3", dependencies=None):
    record = {"type": kind, "resolved": version, "contentHash": HASH}
    if kind in {"Direct", "CentralTransitive"}:
        record["requested"] = "[1.2.3, )"
    if dependencies is not None:
        record["dependencies"] = dependencies
    return record


def write_lock(tmp_path, packages=None, version=1, graphs=None):
    data = {
        "version": version,
        "dependencies": graphs if graphs is not None else {"net8.0": packages or {}},
    }
    (tmp_path / "packages.lock.json").write_text(json.dumps(data), encoding="utf-8")
    return data


@pytest.mark.parametrize("version", [1, 2])
def test_nuget_inventory_direct_transitive_central_and_project(tmp_path, version):
    write_lock(
        tmp_path,
        {
            "Example.Direct": package(dependencies={"Example.Transitive": "1.2.3"}),
            "Example.Transitive": package("Transitive"),
            "Example.Central": package("CentralTransitive"),
            "Example.Project": {"type": "Project", "dependencies": {"Example.Direct": "1.2.3"}},
        },
        version=version,
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert report.manifests_scanned == 1
    assert {(d.name, d.version, d.ecosystem) for d in report.dependencies} == {
        (name, "1.2.3", "NuGet")
        for name in ("Example.Direct", "Example.Transitive", "Example.Central")
    }


def test_nuget_multiple_frameworks_and_runtime_versions(tmp_path):
    write_lock(
        tmp_path,
        graphs={
            "net8.0": {"Example": package(version="1.2.3")},
            "net9.0": {"Example": package(version="2.0.0")},
            "net8.0/linux-x64": {"Example": package(version="1.2.4")},
        },
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert {d.version for d in report.dependencies} == {"1.2.3", "1.2.4", "2.0.0"}


@pytest.mark.parametrize("version", ["1.2.3", "1.2.3.4", "1.2.3-beta.1", "1.2.3+build.1"])
def test_nuget_supported_exact_versions(tmp_path, version):
    write_lock(tmp_path, {"Example": package(version=version)})
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert [d.version for d in report.dependencies] == [version]


@pytest.mark.parametrize("query_osv", [False, True])
def test_nuget_no_source_provenance_never_sends_package_identity(tmp_path, monkeypatch, query_osv):
    write_lock(tmp_path, {"Private.Package": package()})
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("NuGet identity sent"))
    report = audit.audit_dependencies(tmp_path, query_osv=query_osv)
    assert len(report.dependencies) == 1
    assert report.advisory_lookup == ("incomplete" if query_osv else "not_requested")


def test_nuget_dependency_references_are_case_insensitive(tmp_path):
    write_lock(
        tmp_path,
        {"Example": package(dependencies={"other": "1.2.3"}), "Other": package("Transitive")},
    )
    assert audit.audit_dependencies(tmp_path).status == "complete"


def test_nuget_reference_must_exist_in_same_framework(tmp_path):
    write_lock(
        tmp_path,
        graphs={
            "net8.0": {"Example": package(dependencies={"Other": "1.2.3"})},
            "net9.0": {"Other": package("Transitive")},
        },
    )
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


@pytest.mark.parametrize(
    "body",
    [
        '{"version":1,"version":2,"dependencies":{}}',
        '{"version":1,"dependencies":{"net8.0":{},"net8.0":{}}}',
        '{"version":1,"dependencies":{"net8.0":{"Example":{"type":"Transitive","resolved":"1.0.0"},"Example":{"type":"Transitive","resolved":"2.0.0"}}}}',
        '{"version":1,"dependencies":{"net8.0":{"Example":{"type":"Transitive","resolved":"1.0.0","resolved":"2.0.0"}}}}',
        '{"version":1,"dependencies":',
    ],
)
def test_nuget_duplicate_json_keys_and_malformed_json_fail_closed(tmp_path, body):
    (tmp_path / "packages.lock.json").write_text(body)
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


def test_nuget_case_colliding_package_ids_fail_closed(tmp_path):
    write_lock(tmp_path, {"Example": package(), "example": package()})
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


@pytest.mark.parametrize("version", [True, False, 0, 3, "1", None, 1.0])
def test_nuget_unsupported_format_versions(tmp_path, version):
    write_lock(tmp_path, {"Example": package()}, version=version)
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


@pytest.mark.parametrize(
    "record",
    [
        None,
        [],
        "canary-password",
        {},
        {"type": "Unknown", "resolved": "1.2.3"},
        {"type": "Direct", "resolved": 123},
        {"type": "Direct", "resolved": "https://canary-password@example.test"},
        {"type": "Direct", "resolved": "[1.0,2.0)"},
        {"type": "Direct", "resolved": "\u0661.2.3"},
        {"type": "Direct", "resolved": "1.2.3", "dependencies": []},
        {"type": "Direct", "resolved": "1.2.3", "dependencies": {"Other": 123}},
    ],
)
def test_nuget_invalid_records_are_incomplete_and_do_not_echo_values(tmp_path, record):
    write_lock(tmp_path, {"Example": record})
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert "canary-password" not in audit.report_json(report) + audit.report_markdown(report)


@pytest.mark.parametrize(
    "limit,expected_status,expected_count", [(1, "incomplete", 1), (2, "complete", 2)]
)
def test_nuget_dependency_budget_exact_boundary(
    tmp_path, monkeypatch, limit, expected_status, expected_count
):
    write_lock(tmp_path, {"Example": package(), "Other": package("Transitive")})
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", limit)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == expected_status
    assert len(report.dependencies) == expected_count


def test_nuget_invalid_utf8_is_not_disclosed(tmp_path):
    (tmp_path / "packages.lock.json").write_bytes(b"\xffcanary-password")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert "canary-password" not in audit.report_json(report)


@pytest.mark.parametrize("dependencies", [None, [], {"net8.0": []}, {"net8.0": None}])
def test_nuget_invalid_framework_graphs(tmp_path, dependencies):
    (tmp_path / "packages.lock.json").write_text(
        json.dumps({"version": 1, "dependencies": dependencies})
    )
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


def test_nuget_runtime_graph_can_reference_same_framework_base(tmp_path):
    write_lock(
        tmp_path,
        graphs={
            "net8.0": {"Base": package("Transitive")},
            "net8.0/linux-x64": {"Runtime": package(dependencies={"base": "1.2.3"})},
        },
    )
    assert audit.audit_dependencies(tmp_path).status == "complete"


@pytest.mark.parametrize("project", ["Example.csproj", "Example.fsproj", "Example.vbproj"])
def test_nuget_project_without_lock_has_unknown_coverage(tmp_path, project):
    (tmp_path / project).write_text("<Project />")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_nuget_named_project_companion_lock(tmp_path):
    (tmp_path / "Example App.csproj").write_text("<Project />")
    write_lock(tmp_path, {"Example": package()})
    (tmp_path / "packages.lock.json").rename(tmp_path / "packages.Example_App.lock.json")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "complete"
    assert report.manifests_scanned == 1
    assert [d.manifest for d in report.dependencies] == ["packages.Example_App.lock.json"]


def test_nuget_other_projects_named_lock_cannot_cover_project(tmp_path):
    (tmp_path / "Example.csproj").write_text("<Project />")
    write_lock(tmp_path, {"Example": package()})
    (tmp_path / "packages.lock.json").rename(tmp_path / "packages.Other.lock.json")
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


def test_nuget_symlink_companion_does_not_cover_project(tmp_path):
    (tmp_path / "Example.csproj").write_text("<Project />")
    target = tmp_path / "outside.json"
    target.write_text(
        json.dumps({"version": 1, "dependencies": {"net8.0": {"Example": package()}}})
    )
    (tmp_path / "packages.lock.json").symlink_to(target)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


@pytest.mark.parametrize(
    "source",
    [
        "https://api.nuget.org/v3/index.json",
        "https://api.nuget.org.evil.test/",
        "https://canary-password@api.nuget.org/",
    ],
)
def test_nuget_spoofed_source_fields_cannot_enable_osv(tmp_path, monkeypatch, source):
    record = package()
    record["source"] = source
    write_lock(tmp_path, {"Private.Package": record})
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("spoofed source queried"))
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert source not in audit.report_json(report) + audit.report_markdown(report)


@pytest.mark.parametrize(
    "name,version,canary",
    [
        ("ghp_" + "Z" * 40, "1.2.3", "ghp_" + "Z" * 40),
        ("Example", "1.2.3-" + "Z" * 40, "Z" * 40),
        ("Example", "1.2.3+" + "Z" * 40, "Z" * 40),
    ],
)
def test_nuget_secret_like_inventory_tokens_are_not_echoed(tmp_path, name, version, canary):
    write_lock(tmp_path, {name: package(version=version)})
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()
    assert canary not in audit.report_json(report) + audit.report_markdown(report)


@pytest.mark.parametrize("count,status", [(100, "complete"), (101, "incomplete")])
def test_nuget_empty_framework_graphs_are_bounded(tmp_path, count, status):
    write_lock(tmp_path, graphs={f"net{i}.0": {} for i in range(count)})
    assert audit.audit_dependencies(tmp_path).status == status


def test_nuget_unhashable_record_type_is_safe(tmp_path):
    write_lock(tmp_path, {"Example": {"type": [], "resolved": "1.2.3"}})
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()


def test_nuget_runtime_graph_requires_base_framework(tmp_path):
    write_lock(tmp_path, graphs={"net8.0/linux-x64": {"Example": package()}})
    assert audit.audit_dependencies(tmp_path).status == "incomplete"


def test_nuget_case_colliding_reference_names_are_incomplete(tmp_path):
    write_lock(
        tmp_path,
        {
            "Example": package(dependencies={"Other": "1.2.3", "other": "1.2.3"}),
            "Other": package("Transitive"),
        },
    )
    assert audit.audit_dependencies(tmp_path).status == "incomplete"
