"""Read-only application service and deterministic report serialization."""

import html
import json
from collections.abc import Iterable

from .domain import RepositoryTarget, SecurityFinding
from .provider import GitHubSecurityProvider


def scan(target: RepositoryTarget, provider: GitHubSecurityProvider) -> list[SecurityFinding]:
    """Collect findings without mutating remote state."""

    return list(provider.list_findings(target))


def report_json(
    target: RepositoryTarget,
    findings: Iterable[SecurityFinding],
    *,
    provider: str = "unknown",
) -> str:
    """Serialize a stable, secret-free inventory for automation."""

    rows = [
        {
            "alert_class": finding.alert_class.value,
            "identifier": finding.identifier,
            "title": finding.title,
            "severity": finding.severity.value,
            "state": finding.state,
            "repository": finding.repository or target.full_name,
            "rule_id": finding.rule_id,
            "dependency": finding.dependency,
            "fixed_version": finding.fixed_version,
        }
        for finding in findings
    ]
    return json.dumps(
        {
            "schema_version": 1,
            "report_type": "github_alerts",
            "provider": provider,
            "status": "complete",
            "repository": target.full_name,
            "base_branch": target.base_branch,
            "findings": rows,
        },
        indent=2,
        sort_keys=True,
    )


def _markdown_cell(value: str) -> str:
    return (
        html.escape(value, quote=False)
        .replace("|", r"\|")
        .replace("`", "&#96;")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
        .replace("*", "&#42;")
        .replace("_", "&#95;")
        .replace("\n", " ")
    )


def report_markdown(target: RepositoryTarget, findings: Iterable[SecurityFinding]) -> str:
    rows = list(findings)
    lines = [
        f"# Security report: {_markdown_cell(target.full_name)}",
        "",
        f"Open findings: **{len(rows)}**",
        "",
    ]
    if not rows:
        return "\n".join([*lines, "No findings returned by the read-only provider.", ""])
    lines.extend(["| Class | ID | Severity | Title |", "|---|---|---|---|"])
    lines.extend(
        "| "
        + " | ".join(
            _markdown_cell(value)
            for value in (f.alert_class.value, f.identifier, f.severity.value, f.title)
        )
        + " |"
        for f in rows
    )
    return "\n".join([*lines, ""])
