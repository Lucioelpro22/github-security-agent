import io
from email.message import Message
from urllib.error import HTTPError
from urllib.request import Request

import pytest

from github_security_agent.http_transport import RejectRedirects, urlopen_no_redirect


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_redirects_rejected_without_constructing_followup_request(code, method):
    request = Request(
        "https://api.github.com/endpoint",
        method=method,
        headers={"Authorization": "Bearer synthetic-test"},
        data=b"private-package-name" if method == "POST" else None,
    )
    headers = Message()
    headers["Location"] = "https://attacker.invalid/collect"
    handler = RejectRedirects()
    with pytest.raises(HTTPError) as exc:
        getattr(handler, f"http_error_{code}")(request, io.BytesIO(), code, "redirect", headers)
    assert exc.value.code == code
    assert "attacker" not in str(exc.value)
    assert "synthetic-test" not in str(exc.value)


def test_transport_installs_redirect_rejection_and_preserves_timeout(monkeypatch):
    seen = []

    class Opener:
        def open(self, request, *, timeout):
            seen.append((request, timeout))
            return "response"

    def build(handler):
        assert isinstance(handler, RejectRedirects)
        return Opener()

    monkeypatch.setattr("github_security_agent.http_transport.build_opener", build)
    request = Request("https://api.osv.dev/v1/querybatch", data=b"{}")
    assert urlopen_no_redirect(request, timeout=5) == "response"
    assert seen == [(request, 5)]
