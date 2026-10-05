"""Bounded, read-only GitHub REST API provider."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any

from .domain import AlertClass, RepositoryTarget, SecurityFinding, Severity

API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"
REQUEST_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 2_000_000
PER_PAGE = 100
MAX_PAGES_PER_ALERT_CLASS = 10
_OWNER_OR_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_NEXT_LINK = re.compile(r'<([^>]+)>;\s*rel="?next"?', re.IGNORECASE)


class GitHubProviderError(RuntimeError):
    """Safe, user-facing provider error; never contains the token or raw response."""


class GitHubApiProvider:
    """Read open Dependabot, code-scanning, and secret-scanning alerts."""

    def __init__(self, token: str) -> None:
        if not token or not token.strip():
            raise ValueError("GitHub token is required")
        self._token = token.strip()

    def list_findings(self, target: RepositoryTarget) -> Iterable[SecurityFinding]:
        owner = _validate_segment(target.owner, "owner")
        repository = _validate_segment(target.name, "repository")
        base = f"{API_BASE}/repos/{owner}/{repository}"
        endpoints = (
            ("dependabot", f"{base}/dependabot/alerts?state=open"),
            ("code_scanning", f"{base}/code-scanning/alerts?state=open"),
            ("secret_scanning", f"{base}/secret-scanning/alerts?state=open&hide_secret=true"),
        )
        findings: list[SecurityFinding] = []
        for alert_class, endpoint in endpoints:
            findings.extend(self._list_alerts(target, alert_class, endpoint))
        return findings

    def _list_alerts(
        self, target: RepositoryTarget, alert_class: str, endpoint: str
    ) -> list[SecurityFinding]:
        url = _page_url(endpoint, 1)
        findings: list[SecurityFinding] = []
        for page_number in range(1, MAX_PAGES_PER_ALERT_CLASS + 1):
            payload, link_header = self._get_page(url)
            if not isinstance(payload, list):
                raise GitHubProviderError("GitHub returned an unexpected alert response")
            for item in payload:
                if not isinstance(item, dict):
                    raise GitHubProviderError("GitHub returned an unexpected alert response")
                findings.append(_normalize_alert(target, alert_class, item))
            next_url = _next_url(link_header, endpoint)
            if next_url is None:
                return findings
            if page_number == MAX_PAGES_PER_ALERT_CLASS:
                raise GitHubProviderError(
                    f"GitHub {alert_class} alert results exceeded the configured page limit"
                )
            url = next_url
        raise GitHubProviderError("GitHub pagination did not complete")

    def _get_page(self, url: str) -> tuple[Any, str | None]:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "github-security-agent",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                link_header = response.headers.get("Link")
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                message = "GitHub authentication failed; check the configured token"
            elif exc.code == 403:
                message = "GitHub denied access; check read permissions and API rate limits"
            elif exc.code == 404:
                message = "GitHub repository or alert feature was not found or is not accessible"
            else:
                message = f"GitHub API request failed with HTTP {exc.code}"
            raise GitHubProviderError(message) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise GitHubProviderError("GitHub API request failed; check network connectivity") from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise GitHubProviderError("GitHub API response exceeded the configured size limit")
        try:
            return json.loads(body), link_header
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GitHubProviderError("GitHub returned an invalid JSON response") from None


def _validate_segment(value: str, label: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or not _OWNER_OR_REPO.fullmatch(value)
        or value.startswith("-")
    ):
        raise ValueError(f"Invalid GitHub repository {label}")
    return urllib.parse.quote(value, safe="")


def _page_url(endpoint: str, page: int) -> str:
    separator = "&" if "?" in endpoint else "?"
    return f"{API_BASE}{endpoint}{separator}per_page={PER_PAGE}&page={page}"


def _next_url(link_header: str | None, endpoint: str) -> str | None:
    if not link_header:
        return None
    next_url = None
    for item in link_header.split(","):
        match = _NEXT_LINK.search(item.strip())
        if match:
            next_url = match.group(1)
            break
    if next_url is None:
        return None
    parsed = urllib.parse.urlsplit(next_url)
    if parsed.scheme != "https" or parsed.netloc != "api.github.com":
        raise GitHubProviderError("GitHub returned an unsafe pagination link")
    expected_path = urllib.parse.urlsplit(API_BASE + endpoint).path
    query = urllib.parse.parse_qs(parsed.query)
    if (
        parsed.path != expected_path
        or query.get("state") != ["open"]
        or query.get("per_page") != [str(PER_PAGE)]
        or len(query.get("page", [])) != 1
        or not query["page"][0].isdigit()
    ):
        raise GitHubProviderError("GitHub returned an unexpected pagination link")
    return next_url


def _severity(value: Any) -> Severity:
    if not isinstance(value, str):
        return Severity.UNKNOWN
    normalized = value.lower()
    if normalized in {"critical", "high"}:
        return Severity.CRITICAL if normalized == "critical" else Severity.HIGH
    if normalized in {"moderate", "medium", "warning"}:
        return Severity.MEDIUM
    if normalized in {"low", "note"}:
        return Severity.LOW
    if normalized == "error":
        return Severity.HIGH
    return Severity.UNKNOWN


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalize_alert(
    target: RepositoryTarget, alert_class: str, item: dict[str, Any]
) -> SecurityFinding:
    number = item.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise GitHubProviderError("GitHub returned an alert without a valid identifier")

    if alert_class == "dependabot":
        dependency = _mapping(item.get("dependency"))
        package = _mapping(dependency.get("package"))
        advisory = _mapping(item.get("security_advisory"))
        vulnerability = _mapping(item.get("security_vulnerability"))
        patched = _mapping(vulnerability.get("first_patched_version"))
        return SecurityFinding(
            AlertClass.DEPENDABOT,
            str(number),
            _safe_text(advisory.get("summary")) or "Dependabot security alert",
            severity=_severity(vulnerability.get("severity")),
            state="open",
            repository=target.full_name,
            dependency=_safe_text(package.get("name")) or None,
            fixed_version=_safe_text(patched.get("identifier")) or None,
        )

    if alert_class == "code_scanning":
        rule = _mapping(item.get("rule"))
        return SecurityFinding(
            AlertClass.CODE_SCANNING,
            str(number),
            _safe_text(rule.get("description")) or "Code scanning alert",
            severity=_severity(rule.get("security_severity_level") or rule.get("severity")),
            state="open",
            repository=target.full_name,
            rule_id=_safe_text(rule.get("id")) or None,
        )

    secret_type = _safe_text(item.get("secret_type_display_name")) or _safe_text(
        item.get("secret_type")
    )
    return SecurityFinding(
        AlertClass.SECRET_SCANNING,
        str(number),
        secret_type or "Secret scanning alert",
        severity=Severity.UNKNOWN,
        state="open",
        repository=target.full_name,
    )


def _safe_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:500]
