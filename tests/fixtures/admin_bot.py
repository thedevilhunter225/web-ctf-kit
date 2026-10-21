"""Reflected XSS + admin-bot /report workflow. TEST FIXTURE ONLY.

``/`` reflects ``html_input`` unescaped (the XSS). ``/report`` simulates the admin
bot by recording an in-scope visit (it does not fetch external hosts). ``/flagbox``
returns the flag only to a request carrying the admin cookie, modelling the
"make the bot leak an admin-only secret" objective.
"""
from __future__ import annotations

from .wsgi_common import first, form, query, respond

_FORM = ('<html><body><h2>Report a page to admin</h2>'
         '<form method="POST" action="/">'
         '<textarea name="html_input"></textarea><button>Preview</button></form>'
         '<form method="POST" action="/report"><input name="url"><button>Report</button></form>')


def make_app(flag: str = "flag{admin_bot_demo}"):
    state = {"visits": 0, "last": ""}

    def app(environ, start_response):
        path = environ.get("PATH_INFO", "/")
        method = environ["REQUEST_METHOD"]
        data = query(environ)
        if method == "POST":
            data.update(form(environ))
        if path == "/report" and method == "POST":
            state["visits"] += 1
            state["last"] = first(data, "url")
            return respond(start_response,
                           '{"status":"visited","count":%d}' % state["visits"],
                           ctype="application/json")
        if path == "/flagbox":
            if "role=admin" in environ.get("HTTP_COOKIE", ""):
                return respond(start_response, flag)
            return respond(start_response, "forbidden", status="403 Forbidden")
        payload = first(data, "html_input")
        return respond(start_response, f"{_FORM}<div class='preview'>{payload}</div></body></html>")
    return app


app = make_app()
