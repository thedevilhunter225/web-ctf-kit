"""Reflected XSS with a tag/attribute blacklist (bypassable). TEST FIXTURE ONLY."""
from __future__ import annotations

import html as htmllib

from .wsgi_common import first, form, query, respond

# A naive blacklist: these substrings get the whole input HTML-escaped. A broken
# tag / uncommon handler slips through — exactly the "bypass the blacklist" task.
BLACKLIST = ["<script", "<h1", "<img", "<svg", "onerror", "onfocus",
             "<details", "ontoggle"]

_FORM = ('<html><body><h2>Guestbook</h2>'
         '<form method="POST" action="/">'
         '<textarea name="html_input"></textarea>'
         '<input name="q" placeholder="search">'
         '<button>Submit</button></form>'
         '<a href="/about">about</a>')


def make_app():
    def app(environ, start_response):
        path = environ.get("PATH_INFO", "/")
        data = query(environ)
        if environ["REQUEST_METHOD"] == "POST":
            data.update(form(environ))
        if path == "/about":
            return respond(start_response, "<html><body>About this guestbook.</body></html>")
        payload = first(data, "html_input") or first(data, "q")
        reflected = payload
        if any(b in payload.lower() for b in BLACKLIST):
            reflected = htmllib.escape(payload)  # "sanitized"
        return respond(start_response, f"{_FORM}<div class='out'>{reflected}</div></body></html>")
    return app


app = make_app()
