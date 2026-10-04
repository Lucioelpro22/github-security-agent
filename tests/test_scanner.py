from pathlib import Path

from github_security_agent.models import ScanPolicy
from github_security_agent.redaction import redact
from github_security_agent.scanner import scan_directory, scan_text


def test_secrets_are_reported_without_values():
    findings = scan_text("TOKEN = ghp_123456789012345678901234567890", "x.py")
    assert findings[0].rule_id == "secret.github-token"
    assert "123456" not in findings[0].message


def test_actions_risk_rules():
    text = "permissions: write-all\nuses: pull_request_target\n"
    ids = {item.rule_id for item in scan_text(text, ".github/workflows/ci.yml")}
    assert {"actions.write-all", "actions.untrusted-code"} <= ids


def test_directory_limits_and_git_exclusion(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "secret.txt").write_text("ghp_123456789012345678901234567890")
    (tmp_path / "ok.txt").write_text("hello")
    assert len(scan_directory(tmp_path, ScanPolicy())) == 0


def test_redaction():
    assert "ghp_" not in redact("Authorization: Bearer ghp_123456789012345678901234567890")
