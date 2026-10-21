"""Same-origin HTTP transport and target scoping. No third-party dependencies.

This module is the only place that performs outbound network I/O. Every request
is pinned to a single authorized origin (scheme + host + port). Redirects that
leave that origin are refused rather than followed, so a misbehaving or
malicious challenge cannot make the tool reach out to an unrelated host.
"""
from __future__ import annotations

import http.cookiejar
import json as _json
import secrets
import time
from dataclasses import dataclass, field
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse, urlencode
from urllib.request import (
    HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, HTTPHandler,
    ProxyHandler, Request, build_opener,
)

MAX_BODY = 512 * 1024
USER_AGENT = "WebCTFKit/0.2 (authorized CTF target only)"


def origin(url: str) -> tuple[str, str, int]:
    """Return ``(scheme, host, port)`` or raise ``ValueError`` for bad URLs."""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Expected an http(s) URL with a hostname and no embedded credentials")
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    return p.scheme.lower(), p.hostname.lower().rstrip("."), port


def in_scope(base: str, destination: str) -> bool:
    """True only when *destination* is the exact same origin as *base*."""
    try:
        return origin(base) == origin(destination)
    except ValueError:
        return False


def normalize(url: str) -> str:
    """Drop the fragment; keep everything else intact."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def _multipart(fields: dict, files: dict) -> tuple[str, bytes]:
    """Build a multipart/form-data body. *files* maps name -> (filename, content, ctype)."""
    boundary = "----WebCTFKit" + secrets.token_hex(12)
    sep = ("--" + boundary).encode()
    out = bytearray()
    for name, value in fields.items():
        out += sep + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + str(name).encode() + b'"\r\n\r\n'
        out += str(value).encode() + b"\r\n"
    for name, spec in files.items():
        filename, content, ctype = spec
        if isinstance(content, str):
            content = content.encode("latin-1", "replace")
        out += sep + b"\r\n"
        out += (b'Content-Disposition: form-data; name="' + str(name).encode()
                + b'"; filename="' + str(filename).encode() + b'"\r\n')
        out += b"Content-Type: " + str(ctype).encode() + b"\r\n\r\n"
        out += content + b"\r\n"
    out += sep + b"--\r\n"
    return boundary, bytes(out)


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed: float = 0.0
    truncated: bool = False

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class ScopedRedirect(HTTPRedirectHandler):
    """Refuse to follow a redirect that leaves the authorized origin."""

    def __init__(self, base: str):
        self.base = base
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        absolute = urljoin(req.full_url, newurl)
        if not in_scope(self.base, absolute):
            raise HTTPError(req.full_url, code, "Outside challenge scope: redirect blocked", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, absolute)


class Transport:
    """A tiny scoped HTTP client built on :mod:`urllib`.

    Only ``GET`` and ``POST`` are supported. ``Host``/``Content-Length``/
    ``Transfer-Encoding`` cannot be overridden (prevents request smuggling and
    host confusion), and header values containing CR/LF are rejected.
    """

    def __init__(self, target: str, timeout: float = 8.0, cookie: str = "",
                 headers: Mapping[str, str] | None = None, delay: float = 0.1):
        self.target = normalize(target)
        origin(target)  # Fail fast on invalid scope.
        self.timeout = timeout
        self.cookie = cookie
        self.delay = delay
        self.headers = dict(headers or {})
        self.jar = http.cookiejar.CookieJar()
        self.opener = build_opener(
            ProxyHandler({}), HTTPHandler(), HTTPSHandler(),
            HTTPCookieProcessor(self.jar), ScopedRedirect(self.target),
        )
        self.count = 0

    def request(self, url: str, method: str = "GET",
                data: dict[str, str] | None = None,
                json: object | None = None,
                files: dict | None = None) -> Response:
        absolute = normalize(urljoin(self.target, url))
        if not in_scope(self.target, absolute):
            raise ValueError("Out-of-scope URL blocked: " + absolute)
        method = method.upper()
        if json is not None or files is not None:
            method = "POST"  # a JSON/multipart body implies POST
        if method not in ("GET", "POST"):
            raise ValueError("Only GET and POST are supported")
        body_ctype = ""
        if files is not None:
            boundary, values = _multipart(data or {}, files)
            body_ctype = "multipart/form-data; boundary=" + boundary
        elif json is not None:
            values = _json.dumps(json).encode("utf-8")
            body_ctype = "application/json"
        elif method == "POST":
            values = urlencode(data or {}).encode("utf-8")
            body_ctype = "application/x-www-form-urlencoded"
        else:
            values = None
        headers = {"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"}
        for k, v in self.headers.items():
            if not k.isascii() or any(x in k + v for x in "\r\n"):
                raise ValueError("Invalid header")
            if k.lower() in ("host", "content-length", "transfer-encoding"):
                raise ValueError("Cannot override Host/Content-Length/Transfer-Encoding")
            headers[k] = v
        if self.cookie:
            headers["Cookie"] = self.cookie
        if body_ctype:
            headers["Content-Type"] = body_ctype
        req = Request(absolute, data=values, headers=headers, method=method)
        if self.count and self.delay:
            time.sleep(self.delay)
        self.count += 1
        start = time.monotonic()
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                return self._read(response, start)
        except HTTPError as error:
            with error:  # urllib raises for non-2xx and blocked redirects.
                return self._read(error, start)
        except (URLError, TimeoutError, OSError) as exc:
            raise ConnectionError(str(exc)) from exc

    @staticmethod
    def _read(response, start: float) -> Response:
        raw = response.read(MAX_BODY + 1)
        headers = {k.lower(): v for k, v in response.headers.items()}
        charset = response.headers.get_content_charset() or "utf-8"
        try:
            text = raw[:MAX_BODY].decode(charset, errors="replace")
        except LookupError:
            text = raw[:MAX_BODY].decode("utf-8", errors="replace")
        return Response(url=response.url, status=response.code, headers=headers,
                        text=text, elapsed=time.monotonic() - start,
                        truncated=len(raw) > MAX_BODY)


@dataclass
class Target:
    """A scoped transport plus cached metadata about the landing page."""

    url: str
    transport: Transport
    landing: Response | None = None
    fingerprint: dict[str, object] = field(default_factory=dict)

    @classmethod
    def create(cls, url: str, timeout: float = 8.0, cookie: str = "",
               headers: Mapping[str, str] | None = None, delay: float = 0.1) -> "Target":
        transport = Transport(url, timeout=timeout, cookie=cookie,
                              headers=headers, delay=delay)
        return cls(url=transport.target, transport=transport)

    def fetch_landing(self) -> Response:
        if self.landing is None:
            self.landing = self.transport.request(self.url)
        return self.landing
