"""CTF admin-bot / report-endpoint workflow (scope-safe).

Many web CTFs expose a ``/report`` or ``/visit`` endpoint that makes an internal
headless browser visit a URL you supply (the "admin bot"). This helper builds a
single visit URL and submits it to the report endpoint on the *same origin* as
the challenge. It deliberately does not exfiltrate anything to third parties:
there is no external callback by default.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..core.target import Response, Transport, in_scope


def build_visit_url(*, visit_url: str | None = None, bot_base: str | None = None,
                    inject_param: str | None = None, payload: str | None = None) -> str:
    """Construct the URL the admin bot should visit.

    Either pass a complete ``visit_url``, or a ``bot_base`` plus an optional
    ``inject_param``/``payload`` to splice a payload into a query parameter.
    """
    if visit_url:
        if bot_base or inject_param:
            raise ValueError("visit_url cannot be combined with bot_base/inject_param")
        return visit_url
    if not bot_base:
        raise ValueError("Provide visit_url or bot_base")
    if not inject_param:
        return bot_base
    if payload is None:
        raise ValueError("inject_param requires a payload")
    parts = urlsplit(bot_base)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("Invalid bot_base URL")
    values = dict(parse_qsl(parts.query, keep_blank_values=True))
    values[inject_param] = payload
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(values), parts.fragment))


def submit_report(target_url: str, visit_url: str, *, report_path: str = "/report",
                  report_field: str = "url", timeout: float = 12.0,
                  cookie: str = "") -> Response:
    """POST *visit_url* to the challenge's report endpoint (same origin only)."""
    endpoint = urljoin(target_url, report_path)
    if not in_scope(target_url, endpoint):
        raise ValueError("The report endpoint must be on the challenge's origin")
    transport = Transport(target_url, timeout=timeout, cookie=cookie)
    return transport.request(endpoint, method="POST", data={report_field: visit_url})
