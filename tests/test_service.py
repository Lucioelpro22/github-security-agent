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
    assert payload["schema_version"] == 1
    assert payload["provider"] == "unknown"
    assert payload["status"] == "complete"
    assert "internal" not in payload["findings"][0]


def test_markdown_report_escapes_untrusted_alert_text() -> None:
    target = RepositoryTarget("owner", "repo")
    finding = SecurityFinding(
        AlertClass.CODE_SCANNING,
        "alert-1",
        "<script>alert(1)</script> [click](javascript:alert(1)) | title",
    )

    output = report_markdown(target, [finding])

    assert "<script>" not in output
    assert "[click]" not in output
    assert "javascript:" in output
    assert r"\|" in output
