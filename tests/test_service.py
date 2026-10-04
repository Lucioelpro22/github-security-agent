import json

from github_security_agent.domain import AlertClass, RepositoryTarget, SecurityFinding, Severity
from github_security_agent.provider import EmptyProvider
from github_security_agent.service import report_json, report_markdown, scan


def test_empty_provider_is_offline_and_read_only() -> None:
    target = RepositoryTarget("owner", "repo")
    assert scan(target, EmptyProvider()) == []
    assert "No findings" in report_markdown(target, [])


def test_json_report_excludes_metadata_and_is_parseable() -> None:
    target = RepositoryTarget("owner", "repo")
    finding = SecurityFinding(
        AlertClass.CODE_SCANNING,
        "rule-1",
        "Unsafe pattern",
        severity=Severity.HIGH,
        metadata={"internal": "do not export"},
    )
    payload = json.loads(report_json(target, [finding]))
    assert payload["findings"][0]["severity"] == "high"
    assert "internal" not in payload["findings"][0]
