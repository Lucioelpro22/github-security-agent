import io
import json
import urllib.error
import urllib.parse

import pytest

from github_security_agent.domain import AlertClass, RepositoryTarget, Severity
from github_security_agent.github_provider import (
    GitHubApiProvider,
    GitHubProviderError,
    _next_url,
    _validate_segment,
)
from github_security_agent.service import report_json

TOKEN = "test-token-never-print"


class FakeResponse:
    def __init__(self, body, link=None):
        self._body = json.dumps(body).encode()
        self.headers = {"Link": link} if link else {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, limit):
        assert limit > len(self._body)
        return self._body


def test_provider_reads_three_alert_classes_and_never_exports_secret(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        parsed_url = urllib.parse.urlsplit(request.full_url)
        assert parsed_url.scheme == "https"
        assert parsed_url.netloc == "api.github.com"
        assert parsed_url.path.startswith("/repos/owner/repo/")
        assert timeout == 10
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") == f"Bearer {TOKEN}"
        request_headers = {key.lower(): value for key, value in request.header_items()}
        assert request_headers["x-github-api-version"] == "2022-11-28"
        if "/dependabot/alerts" in request.full_url:
            return FakeResponse(
                [
                    {
                        "number": 1,
                        "dependency": {"package": {"name": "demo-package"}},
                        "security_advisory": {"summary": "Unsafe package"},
                        "security_vulnerability": {
                            "severity": "high",
                            "first_patched_version": {"identifier": "2.0.0"},
                        },
                    }
                ]
            )
        if "/code-scanning/alerts" in request.full_url:
            return FakeResponse(
                [
                    {
                        "number": 2,
                        "rule": {
                            "id": "py/unsafe",
                            "description": "Unsafe flow",
                            "security_severity_level": "critical",
                        },
                    }
                ]
            )
        assert "hide_secret=true" in request.full_url
        return FakeResponse(
            [
                {
                    "number": 3,
                    "secret_type_display_name": "GitHub token",
                    "secret": "DO_NOT_EXPORT_LITERAL",
                }
            ]
        )

    monkeypatch.setattr(
        "github_security_agent.github_provider.urllib.request.urlopen", fake_urlopen
    )
    findings = list(GitHubApiProvider(TOKEN).list_findings(RepositoryTarget("owner", "repo")))

    assert len(requests) == 3
    assert [finding.alert_class for finding in findings] == [
        AlertClass.DEPENDABOT,
        AlertClass.CODE_SCANNING,
        AlertClass.SECRET_SCANNING,
    ]
    assert findings[0].severity == Severity.HIGH
    assert findings[0].dependency == "demo-package"
    assert findings[0].fixed_version == "2.0.0"
    assert findings[1].severity == Severity.CRITICAL
    assert findings[2].title == "GitHub token"
    assert "DO_NOT_EXPORT_LITERAL" not in report_json(RepositoryTarget("owner", "repo"), findings)


def test_provider_follows_only_same_origin_next_pages(monkeypatch):
    seen = []

    def fake_urlopen(request, timeout):
        seen.append(request.full_url)
        if (
            "/dependabot/alerts" in request.full_url
            and urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query).get("page") == ["1"]
        ):
            return FakeResponse(
                [{"number": 1, "security_advisory": {"summary": "First"}}],
                '<https://api.github.com/repos/owner/repo/dependabot/alerts?state=open&per_page=100&page=2>; type="application/json"; rel="next"',
            )
        if "/dependabot/alerts" in request.full_url:
            return FakeResponse([{"number": 2, "security_advisory": {"summary": "Second"}}])
        return FakeResponse([])

    monkeypatch.setattr(
        "github_security_agent.github_provider.urllib.request.urlopen", fake_urlopen
    )
    findings = list(GitHubApiProvider(TOKEN).list_findings(RepositoryTarget("owner", "repo")))

    assert [finding.identifier for finding in findings] == ["1", "2"]
    assert any("page=2" in url for url in seen)


def test_secret_scanning_pagination_requires_hide_secret():
    endpoint = "/repos/owner/repo/secret-scanning/alerts?state=open&hide_secret=true"
    unsafe = '<https://api.github.com/repos/owner/repo/secret-scanning/alerts?state=open&per_page=100&page=2>; rel="next"'

    with pytest.raises(GitHubProviderError, match="unexpected pagination"):
        _next_url(unsafe, endpoint, expected_page=2)


def test_provider_rejects_external_pagination_url():
    endpoint = "/repos/owner/repo/dependabot/alerts?state=open"
    header = '<https://example.com/steal?state=open&per_page=100&page=2>; rel="next"'

    with pytest.raises(GitHubProviderError, match="unsafe pagination"):
        _next_url(header, endpoint, expected_page=2)


def test_provider_reports_http_status_without_body_or_token(monkeypatch):
    def fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            403,
            "forbidden",
            hdrs=None,
            fp=io.BytesIO(f"{TOKEN} sensitive response".encode()),
        )

    monkeypatch.setattr(
        "github_security_agent.github_provider.urllib.request.urlopen", fake_urlopen
    )
    provider = GitHubApiProvider(TOKEN)

    with pytest.raises(GitHubProviderError, match="read permissions") as caught:
        list(provider.list_findings(RepositoryTarget("owner", "repo")))

    assert TOKEN not in str(caught.value)
    assert "sensitive response" not in str(caught.value)


def test_provider_fails_closed_when_page_limit_is_reached(monkeypatch):
    monkeypatch.setattr("github_security_agent.github_provider.MAX_PAGES_PER_ALERT_CLASS", 1)

    def fake_urlopen(request, timeout):
        return FakeResponse(
            [{"number": 1}],
            '<https://api.github.com/repos/owner/repo/dependabot/alerts?state=open&per_page=100&page=2>; rel="next"',
        )

    monkeypatch.setattr(
        "github_security_agent.github_provider.urllib.request.urlopen", fake_urlopen
    )

    with pytest.raises(GitHubProviderError, match="page limit"):
        list(GitHubApiProvider(TOKEN).list_findings(RepositoryTarget("owner", "repo")))


@pytest.mark.parametrize("value", ["", ".", "..", "../repo", "-owner", "owner/repo"])
def test_repository_segments_are_validated(value):
    with pytest.raises(ValueError):
        _validate_segment(value, "owner")


def test_token_required():
    with pytest.raises(ValueError, match="token is required"):
        GitHubApiProvider(" ")
