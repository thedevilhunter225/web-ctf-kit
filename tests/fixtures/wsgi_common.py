"""Small WSGI helpers shared by the fixtures."""
from __future__ import annotations

from urllib.parse import parse_qs


def query(environ) -> dict[str, list[str]]:
    return parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)


def form(environ) -> dict[str, list[str]]:
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    raw = environ["wsgi.input"].read(length) if length else b""
    return parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)


def first(data: dict, key: str, default: str = "") -> str:
    values = data.get(key)
    return values[0] if values else default


def respond(start_response, body, status: str = "200 OK", headers=None,
            ctype: str = "text/html; charset=utf-8"):
    data = body.encode("utf-8") if isinstance(body, str) else body
    out_headers = [("Content-Type", ctype), ("Content-Length", str(len(data)))]
    if headers:
        out_headers.extend(headers)
    start_response(status, out_headers)
    return [data]
