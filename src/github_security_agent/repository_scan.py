"""Bounded, read-only local repository scanner. Repository files are data, never executed."""

from __future__ import annotations

import html
import json
import os
import re
import stat
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 25_000_000
MAX_FILES = 10_000
MAX_FINDINGS = 5_000
MAX_SCAN_SECONDS = 30
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
BINARY_SUFFIXES = {".7z", ".bmp", ".dll", ".dylib", ".exe", ".gif", ".gz", ".ico", ".jpeg", ".jpg", ".pdf", ".png", ".so", ".tar", ".webp", ".woff", ".woff2", ".zip"}


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: str
    confidence: str
    file: str
    line: int
    summary: str
    recommendation: str


@dataclass(frozen=True, slots=True)
class ScanReport:
    root: str
    status: Literal["complete", "incomplete"]
    files_scanned: int
    files_skipped: int
    files_unsupported: int
    findings: tuple[Finding, ...]


_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "secret.github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    ),
    ("secret.aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret.slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("secret.private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "secret.credential_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|client[_-]?secret|password|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{24,})"
        ),
    ),
)
_PLACEHOLDERS = {"x" * 24, "0" * 24, "changeme", "replace_me", "your_token_here", "example"}
_ACTION_USE = re.compile(r"^\s*-?\s*uses\s*:\s*([^\s#]+)")
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


def _secret_rule(line: str) -> str | None:
    for rule_id, pattern in _SECRET_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        value = match.group(1) if rule_id == "secret.credential_assignment" else match.group(0)
        normalized = value.strip("'\" ").lower()
        if "${{" in value:
            continue
        if normalized in _PLACEHOLDERS or normalized.startswith(("your_", "example_", "dummy_")):
            continue
        return rule_id
    return None


def _findings_for(
    path: Path, relative: str, text: str, max_findings: int
) -> tuple[list[Finding], bool]:
    findings: list[Finding] = []
    workflow = relative.startswith(".github/workflows/") and path.suffix.lower() in {
        ".yml",
        ".yaml",
    }
    for line_number, line in enumerate(text.splitlines(), start=1):
        secret_rule = _secret_rule(line)
        if secret_rule:
            findings.append(
                Finding(
                    secret_rule,
                    "high",
                    "medium",
                    relative,
                    line_number,
                    "Potential credential detected; the value was redacted.",
                    "Revoke and rotate the credential if it is real, then move it to a secret manager.",
                )
            )
            if len(findings) >= max_findings:
                return findings, True
        if not workflow or line.lstrip().startswith("#"):
            continue
        if re.match(r"^\\s*permissions\\s*:\\s*write-all\\b", line, re.IGNORECASE):
            findings.append(
                Finding(
                    "workflow.permissions_write_all",
                    "high",
                    "high",
                    relative,
                    line_number,
                    "Workflow grants broad write permissions.",
                    "Declare only the specific permissions the workflow needs, preferably read-only.",
                )
            )
            if len(findings) >= max_findings:
                return findings, True
        if re.search(r"\\bpull_request_target\\s*:", line):
            findings.append(
                Finding(
                    "workflow.pull_request_target",
                    "high",
                    "medium",
                    relative,
                    line_number,
                    "Privileged pull_request_target trigger needs review for untrusted pull request data.",
                    "Avoid checking out or executing fork-controlled content with privileged tokens or secrets.",
                )
            )
            if len(findings) >= max_findings:
                return findings, True
        use = _ACTION_USE.match(line)
        if use:
            reference = use.group(1)
            if reference.startswith(("./", "docker://")):
                continue
            if "@" in reference:
                ref = reference.rsplit("@", 1)[1]
                if not _SHA.fullmatch(ref):
                    findings.append(
                        Finding(
                            "workflow.action_not_sha_pinned",
                            "medium",
                            "high",
                            relative,
                            line_number,
                            "Third-party action is referenced by a mutable version or tag.",
                            "Pin the action to a reviewed full commit SHA and keep its version in a comment.",
                        )
                    )
                    if len(findings) >= max_findings:
                        return findings, True
    return findings, False

def scan_repository(root: str | Path) -> ScanReport:
    """Scan bounded UTF-8 text files without following symlinks or executing code."""
    base = Path(root).resolve(strict=True)
    if not base.is_dir():
        raise ValueError("scan root must be a directory")

    findings: list[Finding] = []
    files_scanned = 0
    files_skipped = 0
    files_unsupported = 0
    total_bytes = 0
    incomplete = False
    limit_reached = False
    started_at = time.monotonic()

    for current, dirs, files in os.walk(base, topdown=True, followlinks=False):
        if time.monotonic() - started_at >= MAX_SCAN_SECONDS:
            incomplete = True
            break
        current_path = Path(current)
        dirs[:] = sorted(
            name
            for name in dirs
            if name not in IGNORED_DIRS and not (current_path / name).is_symlink()
        )
        for name in sorted(files):
            if time.monotonic() - started_at >= MAX_SCAN_SECONDS:
                incomplete = True
                limit_reached = True
                break
            path = current_path / name
            if path.is_symlink():
                continue
            if path.suffix.lower() in BINARY_SUFFIXES:
                files_unsupported += 1
                continue
            if files_scanned + files_skipped + files_unsupported >= MAX_FILES:
                incomplete = True
                limit_reached = True
                break
            remaining_bytes = MAX_TOTAL_BYTES - total_bytes
            read_limit = min(MAX_FILE_BYTES, remaining_bytes)
            if read_limit <= 0:
                files_skipped += 1
                incomplete = True
                limit_reached = True
                break
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(path, flags)
                with os.fdopen(descriptor, "rb") as source:
                    file_info = os.fstat(source.fileno())
                    if not stat.S_ISREG(file_info.st_mode):
                        continue
                    data = source.read(read_limit + 1)
            except OSError:
                files_skipped += 1
                incomplete = True
                continue
            total_bytes += len(data)
            if len(data) > read_limit:
                files_skipped += 1
                incomplete = True
                limit_reached = total_bytes >= MAX_TOTAL_BYTES
                if limit_reached:
                    break
                continue
            if b"\\x00" in data[:8192]:
                files_unsupported += 1
                continue
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                files_unsupported += 1
                continue
            files_scanned += 1
            relative = path.relative_to(base).as_posix()
            remaining_findings = MAX_FINDINGS - len(findings)
            found, findings_truncated = _findings_for(
                path, relative, text, remaining_findings
            )
            findings.extend(found)
            if findings_truncated:
                incomplete = True
                limit_reached = True
                break
        if limit_reached:
            break
        if files_scanned + files_skipped + files_unsupported >= MAX_FILES:
            incomplete = True
            break

    findings.sort(key=lambda finding: (finding.file, finding.line, finding.rule_id))
    return ScanReport(
        root=".",
        status="incomplete" if incomplete else "complete",
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        files_unsupported=files_unsupported,
        findings=tuple(findings),
    )

def report_json(report: ScanReport) -> str:
    return json.dumps(asdict(report), indent=2, sort_keys=True)


def report_markdown(report: ScanReport) -> str:
    lines = [
        "# Local repository security scan",
        "",
        f"- Status: **{report.status}**",
        f"- Files scanned: **{report.files_scanned}**",
        f"- Files skipped (errors or limits): **{report.files_skipped}**",
        f"- Unsupported files skipped: **{report.files_unsupported}**",
        f"- Findings: **{len(report.findings)}**",
        "",
    ]
    if not report.findings:
        lines.append("No findings detected by the enabled rules.")
    else:
        lines.extend(
            ["| Severity | Rule | File:line | Finding | Recommendation |", "|---|---|---|---|---|"]
        )
        for item in report.findings:
            safe_file = (
                html.escape(item.file, quote=False)
                .replace("|", "&#124;")
                .replace("`", "&#96;")
                .replace("\n", " ")
            )
            safe_summary = (
                html.escape(item.summary, quote=False).replace("|", "&#124;").replace("\n", " ")
            )
            safe_recommendation = (
                html.escape(item.recommendation, quote=False)
                .replace("|", "&#124;")
                .replace("\n", " ")
            )
            lines.append(
                f"| {item.severity} | `{item.rule_id}` | `{safe_file}:{item.line}` "
                f"| {safe_summary} | {safe_recommendation} |"
            )
    lines.extend(["", "This report is advisory; no repository files were changed or executed.", ""])
    return "\n".join(lines)
