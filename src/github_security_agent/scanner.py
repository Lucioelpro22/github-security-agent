"""Offline scanner for repository text and GitHub Actions policy issues."""

import re
from pathlib import Path

from .file_reader import open_repository_root, read_repository_file
from .models import Finding, ScanPolicy

_SECRET_PATTERNS = (
    ("secret.github-token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")),
    ("secret.private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "secret.assignment",
        re.compile(r"(?i)\b(?:password|secret|api[_-]?key)\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    ),
)


def scan_text(text: str, path: str, *, max_findings: int = 100) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for rule_id, pattern in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule_id,
                        "critical",
                        "credential-like material detected; value redacted",
                        path,
                        line_number,
                    )
                )
        stripped = line.strip()
        if stripped.startswith("permissions:") and stripped.endswith("write-all"):
            findings.append(
                Finding(
                    "actions.write-all",
                    "high",
                    "workflow requests broad write permissions",
                    path,
                    line_number,
                )
            )
        if "pull_request_target" in line:
            findings.append(
                Finding(
                    "actions.untrusted-code",
                    "high",
                    "review pull_request_target before executing untrusted code",
                    path,
                    line_number,
                )
            )
        if "github.event.pull_request.title" in line or "github.event.issue.body" in line:
            findings.append(
                Finding(
                    "actions.untrusted-interpolation",
                    "medium",
                    "untrusted event data is interpolated into workflow text",
                    path,
                    line_number,
                )
            )
        if len(findings) >= max_findings:
            return findings[:max_findings]
    return findings


def scan_directory(root: Path, policy: ScanPolicy | None = None) -> list[Finding]:
    policy = policy or ScanPolicy()
    if not root.is_dir():
        raise ValueError("scan root must be a directory")
    root = root.resolve(strict=True)
    with open_repository_root(root) as descriptor:
        return _scan_directory(root, policy, descriptor)


def _scan_directory(root: Path, policy: ScanPolicy, descriptor: int) -> list[Finding]:
    findings: list[Finding] = []
    files_seen = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file() or ".git" in path.parts:
            continue
        files_seen += 1
        if files_seen > policy.max_files:
            raise ValueError("file count exceeds configured limit")
        data = read_repository_file(descriptor, path.relative_to(root), policy.max_file_bytes)
        text = data.decode("utf-8", errors="replace")
        findings.extend(scan_text(text, path.relative_to(root).as_posix()))
    return findings
