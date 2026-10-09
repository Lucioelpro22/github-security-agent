"""Bounded NuGet parsing at the scanner boundary, without network lookups."""

import json

import pytest

from github_security_agent import dependency_audit as audit


def test_nuget_deep_json_is_incomplete_without_disclosing_content(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("unexpected OSV lookup"))
    body = "[" * 10_000 + '"canary-password"' + "]" * 10_000
    (tmp_path / "packages.lock.json").write_text(body)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert report.dependencies == ()
    assert "canary-password" not in audit.report_json(report)


@pytest.mark.parametrize("edge_count,status", [(110, "complete"), (111, "incomplete")])
def test_nuget_reference_budget_boundary(tmp_path, monkeypatch, edge_count, status):
    # Eleven Project nodes allow 121 distinct valid edges without inventory pins.
    # The configured edge budget is ten times the package-entry budget.
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", 11)
    graph = {f"P{i}": {"type": "Project", "dependencies": {}} for i in range(11)}
    for index in range(edge_count):
        graph[f"P{index // 11}"]["dependencies"][f"P{index % 11}"] = "1.2.3"
    (tmp_path / "packages.lock.json").write_text(
        json.dumps({"version": 1, "dependencies": {"net8.0": graph}})
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == status
    assert report.dependencies == ()


def test_nuget_actual_package_budget_preserves_bounded_inventory(tmp_path):
    graph = {f"P{i}": {"type": "Transitive", "resolved": "1.2.3"} for i in range(5_001)}
    (tmp_path / "packages.lock.json").write_text(
        json.dumps({"version": 1, "dependencies": {"net8.0": graph}})
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
    assert len(report.dependencies) == 5_000
    assert all(dependency.source_kind == "unknown" for dependency in report.dependencies)
