"""Optional bounded GitHub reader. It never writes or executes code."""

from urllib.request import Request, urlopen

from .policy import bounded_timeout, validate_url


class ReadOnlyClient:
    def __init__(self, *, timeout: float = 10.0, max_bytes: int = 1_048_576) -> None:
        self.timeout = bounded_timeout(timeout)
        if not 1 <= max_bytes <= 10_485_760:
            raise ValueError("max_bytes must be between 1 and 10 MiB")
        self.max_bytes = max_bytes

    def get_text(self, url: str) -> str:
        validate_url(url)
        request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "github-security-agent/0.1"})
        with urlopen(request, timeout=self.timeout) as response:  # noqa: S310 - URL is allow-listed above
            data = response.read(self.max_bytes + 1)
        if len(data) > self.max_bytes:
            raise ValueError("response exceeds configured size limit")
        return data.decode("utf-8", errors="strict")
