"""Small immutable models used by the scanner."""

from dataclasses import dataclass
from typing import Literal


Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    path: str
    line: int

    def safe_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "line": self.line,
        }


@dataclass(frozen=True)
class ScanPolicy:
    """Bounded policy; network and process execution are intentionally absent."""

    max_file_bytes: int = 1_048_576
    max_files: int = 200
    dry_run: bool = True
    read_only: bool = True

    def __post_init__(self) -> None:
        if not 1 <= self.max_file_bytes <= 10_485_760:
            raise ValueError("max_file_bytes must be between 1 and 10 MiB")
        if not 1 <= self.max_files <= 1_000:
            raise ValueError("max_files must be between 1 and 1000")
        if not self.dry_run or not self.read_only:
            raise ValueError("only dry-run, read-only mode is supported")
