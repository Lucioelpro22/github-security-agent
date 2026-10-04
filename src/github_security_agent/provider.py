"""Provider boundary; implementations must preserve read-only semantics."""

from collections.abc import Iterable
from typing import Protocol

from .domain import RepositoryTarget, SecurityFinding


class GitHubSecurityProvider(Protocol):
    """Read-only contract for GitHub-backed inventory providers."""

    def list_findings(self, target: RepositoryTarget) -> Iterable[SecurityFinding]:
        """Return normalized open findings for one repository."""


class EmptyProvider:
    """Offline provider used by the scaffold and tests."""

    def list_findings(self, target: RepositoryTarget) -> Iterable[SecurityFinding]:
        del target
        return ()
