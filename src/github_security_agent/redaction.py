"""Secret-safe output helpers."""

import re

_PATTERNS = (
    re.compile(r"(?i)(gh[pousr]_[A-Za-z0-9_]{20,})"),
    re.compile(r"(?i)(github_token|token|password|secret|api[_-]?key)\s*[:=]\s*([^\s,;]+)"),
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([^\s]+)"),
)


def redact(text: str) -> str:
    """Redact common credentials without echoing their values."""
    result = _PATTERNS[0].sub("[REDACTED_GITHUB_TOKEN]", text)
    result = _PATTERNS[1].sub(lambda m: f"{m.group(1)}=[REDACTED]", result)
    result = _PATTERNS[2].sub(r"\1[REDACTED]", result)
    return result
