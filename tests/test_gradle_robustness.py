"""Adversarial Gradle physical lines and configuration budget boundaries."""

import pytest

from github_security_agent import dependency_audit as audit


@pytest.mark.parametrize("count,status,pins", [(10, "complete", 1), (11, "incomplete", 0)])
def test_gradle_configuration_budget_boundary(tmp_path, monkeypatch, count, status, pins):
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", 1)
    configurations = ",".join(f"configuration{i}" for i in range(count))
    (tmp_path / "gradle.lockfile").write_text(
        f"org.example:library:1.0={configurations}\nempty=\n", encoding="utf-8"
    )
    report = audit.audit_dependencies(tmp_path)
    assert report.status == status
    assert len(report.dependencies) == pins


@pytest.mark.parametrize("separator", ["\u2028", "\u2029"])
@pytest.mark.parametrize("position", ["between_records", "configuration_padding"])
def test_gradle_unicode_separator_does_not_create_valid_physical_lines(
    tmp_path, separator, position
):
    body = (
        f"org.example:library:1.0=runtimeClasspath{separator}empty=\n"
        if position == "between_records"
        else f"org.example:library:1.0={separator}runtimeClasspath\nempty=\n"
    )
    (tmp_path / "gradle.lockfile").write_text(body, encoding="utf-8")
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"
