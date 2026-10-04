"""Stable domain objects independent from the GitHub API client."""

from dataclasses import dataclass, field
from enum import StrEnum


class AlertClass(StrEnum):
    DEPENDABOT = "dependabot"
    CODE_SCANNING = "code_scanning"
    SECRET_SCANNING = "secret_scanning"
    ACTIONS = "actions"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    """Normalized finding; never stores secret values or full source contents."""

    alert_class: AlertClass
    identifier: str
    title: str
    severity: Severity = Severity.UNKNOWN
    state: str = "open"
    repository: str = ""
    rule_id: str | None = None
    dependency: str | None = None
    fixed_version: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RepositoryTarget:
    owner: str
    name: str
    base_branch: str = "main"

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"
