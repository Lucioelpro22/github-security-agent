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


def test_directory_does_not_read_external_symlink(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "external.txt"
    outside.write_text("ghp_123456789012345678901234567890")
    (root / "linked.txt").symlink_to(outside)
    assert scan_directory(root) == []


def test_directory_unsupported_platform_fails_explicitly(tmp_path, monkeypatch):
    import os

    import pytest

    monkeypatch.setattr(os, "supports_dir_fd", set())
    with pytest.raises(OSError, match="unavailable"):
        scan_directory(tmp_path)


def test_legacy_growth_surfaces_failure(tmp_path, monkeypatch):
    import os

    import pytest

    from github_security_agent import file_reader

    target = tmp_path / "growing"
    target.write_bytes(b"safe")
    original = os.fstat

    def grow(fd):
        metadata = original(fd)
        target.write_bytes(b"x" * 101)
        return metadata

    monkeypatch.setattr(file_reader.os, "fstat", grow)
    with pytest.raises(OSError, match="exceeds"):
        scan_directory(tmp_path, ScanPolicy(max_file_bytes=100))
