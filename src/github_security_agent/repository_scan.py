"""Bounded, read-only local repository scanner. Repository files are data, never executed."""

from __future__ import annotations

import html
import json
import os
import re
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


def _is_environment_file(relative: str) -> bool:
    name = Path(relative).name.lower()
    if name in {".env.example", ".env.sample", ".env.template", ".env.dist"}:
        return False
    return name == ".env" or name.startswith(".env.")


def _is_container_config(relative: str) -> bool:
    path = Path(relative)
    if path.suffix.lower() not in {".yml", ".yaml", ".json"}:
        return False
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    return bool(
        parts.intersection({"k8s", "kubernetes", "manifests", "deploy"})
        or name.startswith(("docker-compose", "compose.", "deployment", "pod."))
    )


_UNTRUSTED_WORKFLOW_VALUE = re.compile(
    r"\$\{\{\s*(?:github\.head_ref|github\.event\."
    r"(?:pull_request\.(?:title|body|head\.(?:ref|label))|"
    r"issue\.(?:title|body)|comment\.body))\s*\}\}",
    re.IGNORECASE,
)
_RUN_KEY = re.compile(r"^(\s*)(?:-\s*)?run\s*:\s*(.*)$", re.IGNORECASE)
_CONFIG_TRUE = re.compile(r"^\s*(?:privileged|allowPrivilegeEscalation)\s*:\s*true\b", re.I)
_CONFIG_ROOT = re.compile(r"^\s*runAsUser\s*:\s*0\b", re.I)
_DOCKER_ROOT_USER = re.compile(r"^\s*USER\s+root\s*(?:#.*)?$", re.I)


def _findings_for(path: Path, relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    workflow = relative.startswith(".github/workflows/") and path.suffix.lower() in {
        ".yml",
        ".yaml",
    }
    container_config = _is_container_config(relative)
    dockerfile = path.name.lower() == "dockerfile" or path.name.lower().startswith("dockerfile.")
    if _is_environment_file(relative):
        findings.append(
            Finding(
                "config.environment_file_present",
                "medium",
                "low",
                relative,
                1,
                "Environment file found; verify it does not contain production values or belong in version control.",
                "Keep real environment files out of version control and use a secret manager; commit only sanitized examples.",
            )
        )

    run_indent: int | None = None
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
        if container_config:
            if _CONFIG_TRUE.match(line):
                key = line.split(":", 1)[0].strip().lower()
                rule_id = (
                    "container.privilege_escalation"
                    if key == "allowprivilegeescalation"
                    else "container.privileged_mode"
                )
                findings.append(
                    Finding(
                        rule_id,
                        "high",
                        "high",
                        relative,
                        line_number,
                        "Container configuration explicitly enables a privileged execution setting.",
                        "Disable the setting unless a documented requirement justifies it; apply least privilege.",
                    )
                )
            if _CONFIG_ROOT.match(line):
                findings.append(
                    Finding(
                        "container.run_as_root",
                        "high",
                        "high",
                        relative,
                        line_number,
                        "Container workload is explicitly configured to run as UID 0.",
                        "Use a dedicated non-root user and apply the minimum filesystem and capability permissions.",
                    )
                )
        if dockerfile and _DOCKER_ROOT_USER.match(line):
            findings.append(
                Finding(
                    "container.dockerfile_root_user",
                    "medium",
                    "high",
                    relative,
                    line_number,
                    "Dockerfile explicitly selects the root user.",
                    "Use a dedicated non-root runtime user where the application permits it.",
                )
            )
        if not workflow:
            continue

        run_match = _RUN_KEY.match(line)
        in_run = False
        if run_match:
            run_indent = len(run_match.group(1).expandtabs(8))
            in_run = bool(run_match.group(2).strip())
        elif run_indent is not None:
            if not line.strip() or line.lstrip().startswith("#"):
                in_run = True
            else:
                indent = len(line) - len(line.lstrip())
                if indent > run_indent:
                    in_run = True
                else:
                    run_indent = None
        if in_run and _UNTRUSTED_WORKFLOW_VALUE.search(line):
            findings.append(
                Finding(
                    "workflow.untrusted_event_interpolation",
                    "high",
                    "high",
                    relative,
                    line_number,
                    "Untrusted pull request or issue data is interpolated into a shell command.",
                    "Pass the value through an environment variable and quote/validate it; avoid direct expression interpolation in run scripts.",
                )
            )

        if re.match(r"^\s*permissions\s*:\s*write-all\b", line, re.IGNORECASE):
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
        if re.search(r"\bpull_request_target\s*:", line):
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
    return findings

def scan_repository(root: str | Path) -> ScanReport:
    """Scan text files under root without following symlinks or executing repository code."""
    base = Path(root).resolve(strict=True)
    if not base.is_dir():
        raise ValueError("scan root must be a directory")

    findings: list[Finding] = []
    files_scanned = 0
    files_skipped = 0
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
            if path.is_symlink() or not path.is_file():
                continue
            if files_scanned + files_skipped >= MAX_FILES:
                incomplete = True
                break
            try:
                size = path.stat().st_size
                if size > MAX_FILE_BYTES or total_bytes + size > MAX_TOTAL_BYTES:
                    files_skipped += 1
                    incomplete = True
                    continue
                data = path.read_bytes()
                total_bytes += len(data)
                text = data.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                files_skipped += 1
                incomplete = True
                continue
            files_scanned += 1
            relative = path.relative_to(base).as_posix()
            findings.extend(_findings_for(path, relative, text))
            if len(findings) >= MAX_FINDINGS:
                findings = findings[:MAX_FINDINGS]
                incomplete = True
                limit_reached = True
                break
        if limit_reached:
            break
        if files_scanned + files_skipped >= MAX_FILES:
            break

    findings.sort(key=lambda finding: (finding.file, finding.line, finding.rule_id))
    return ScanReport(
        root=".",
        status="incomplete" if incomplete else "complete",
        files_scanned=files_scanned,
        files_skipped=files_skipped,
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
        f"- Files skipped: **{report.files_skipped}**",
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
