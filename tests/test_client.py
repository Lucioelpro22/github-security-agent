import io
from email.message import Message
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, build_opener
from urllib.response import addinfourl

import pytest

from github_security_agent.client import ReadOnlyClient


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "destination", ["https://attacker.invalid/collect", "https://api.github.com/other"]
)
def test_client_rejects_redirect_without_contacting_destination(monkeypatch, code, destination):
    requests = []

    class SyntheticHTTPS(HTTPSHandler):
        def https_open(self, request):
            requests.append(request.full_url)
            headers = Message()
            headers["Location"] = destination
            response = addinfourl(io.BytesIO(b""), headers, request.full_url, code)
            response.msg = "Redirect"
            return response

    def synthetic_opener(handler):
        return build_opener(handler, SyntheticHTTPS())

    monkeypatch.setattr("github_security_agent.http_transport.build_opener", synthetic_opener)
    with pytest.raises(HTTPError) as exc:
        ReadOnlyClient().get_text("https://api.github.com/repos/owner/repo")
    assert exc.value.code == code
    assert requests == ["https://api.github.com/repos/owner/repo"]


def test_client_preserves_bounded_read_and_timeout(monkeypatch):
    calls = []

    def open_response(request, *, timeout):
        calls.append((request.full_url, timeout))
        return io.BytesIO(b"12345")

    monkeypatch.setattr("github_security_agent.client.urlopen_no_redirect", open_response)
    client = ReadOnlyClient(timeout=3, max_bytes=4)
    with pytest.raises(ValueError, match="size limit"):
        client.get_text("https://api.github.com/repos/owner/repo")
    assert calls == [("https://api.github.com/repos/owner/repo", 3)]


def test_client_decodes_successful_response(monkeypatch):
    monkeypatch.setattr(
        "github_security_agent.client.urlopen_no_redirect",
        lambda request, timeout: io.BytesIO(b"example"),
    )
    assert ReadOnlyClient().get_text("https://api.github.com/repos/owner/repo") == "example"


@pytest.mark.parametrize("payload", [b"1234", b"\xff"])
def test_client_exact_limit_and_strict_utf8(monkeypatch, payload):
    monkeypatch.setattr(
        "github_security_agent.client.urlopen_no_redirect",
        lambda request, timeout: io.BytesIO(payload),
    )
    client = ReadOnlyClient(max_bytes=4)
    if payload == b"1234":
        assert client.get_text("https://api.github.com/test") == "1234"
    else:
        with pytest.raises(UnicodeDecodeError):
            client.get_text("https://api.github.com/test")


def test_client_rejects_original_off_allowlist_url_before_transport(monkeypatch):
    def unexpected_open(*args, **kwargs):
        pytest.fail("Transport must not run for a forbidden URL")

    monkeypatch.setattr("github_security_agent.client.urlopen_no_redirect", unexpected_open)
    with pytest.raises(ValueError, match="allow-list"):
        ReadOnlyClient().get_text("https://attacker.invalid/test")
