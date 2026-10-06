"""HTTP transport that rejects redirects before forwarding credentials or data."""

from typing import Any, NoReturn
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener


class RejectRedirects(HTTPRedirectHandler):
    def http_error_302(self, req: Request, fp: Any, code: int, msg: str, headers: Any) -> NoReturn:
        raise HTTPError(req.full_url, code, "HTTP redirect blocked", headers, None)

    http_error_301 = http_error_302
    http_error_303 = http_error_302
    http_error_307 = http_error_302
    http_error_308 = http_error_302


def urlopen_no_redirect(request: Request, *, timeout: float) -> Any:
    return build_opener(RejectRedirects()).open(request, timeout=timeout)
