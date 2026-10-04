"""Input validation and bounded URL policy."""

from urllib.parse import urlsplit


ALLOWED_HOSTS = frozenset({"api.github.com", "raw.githubusercontent.com"})


def validate_repo_name(value: str) -> str:
    if not isinstance(value, str) or len(value) > 100 or not value:
        raise ValueError("repository must be a non-empty owner/name string")
    parts = value.split("/")
    if len(parts) != 2 or any(not p or p in {".", ".."} for p in parts):
        raise ValueError("repository must use owner/name form")
    if any(not all(c.isalnum() or c in "-_.@" for c in p) for p in parts):
        raise ValueError("repository contains unsupported characters")
    return value


def validate_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("URL host is not in the GitHub HTTPS allow-list")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("credentials and non-standard ports are forbidden")
    if parsed.fragment:
        raise ValueError("URL fragments are forbidden")
    return value


def bounded_timeout(value: float) -> float:
    if not 0.1 <= value <= 30.0:
        raise ValueError("timeout must be between 0.1 and 30 seconds")
    return value
