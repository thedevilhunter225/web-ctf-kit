"""Prototype-pollution -> privilege-escalation fixture (Smesh-like). TEST ONLY.

Python has no real Object.prototype, so this emulates the *observable* effect of
the JS bug: a settings endpoint that (a) merges a JSON body or (b) builds JSON by
interpolating string fields (the Smesh sink) and then "pollutes" a shared gadget
store if a nested ``__proto__``/``constructor.prototype`` sets an admin gadget.
``/admin`` returns the flag once the session is admin *or* the gadget store was
polluted. It advertises as Express (header + connect.sid cookie) so black-box
detection fires. Deliberately insecure; never deploy.
"""
from __future__ import annotations

import json
import secrets
from http.cookies import SimpleCookie

from .wsgi_common import first, form, query, respond

_HDRS = [("X-Powered-By", "Express")]


def _sid(environ) -> str:
    c = SimpleCookie(environ.get("HTTP_COOKIE", ""))
    return c["connect.sid"].value if "connect.sid" in c else ""


def make_app(flag: str = "flag{pp_privesc_demo}"):
    users: dict[str, dict] = {}
    sessions: dict[str, dict] = {}
    polluted: dict[str, object] = {}  # emulated Object.prototype

    def detect(obj) -> bool:
        found = False
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "__proto__" and isinstance(v, dict):
                    polluted.update(v)
                    found = True
                elif k == "constructor" and isinstance(v, dict) and isinstance(v.get("prototype"), dict):
                    polluted.update(v["prototype"])
                    found = True
                if isinstance(v, (dict, list)):
                    found = detect(v) or found
        elif isinstance(obj, list):
            for it in obj:
                found = detect(it) or found
        return found

    def is_admin(sess) -> bool:
        if not sess:
            return False
        return (sess.get("role") == "admin"
                or polluted.get("role") == "admin"
                or polluted.get("isAdmin") in (True, "true", 1)
                or polluted.get("admin") in (True, "true", 1))

    def body_json(environ):
        try:
            ln = int(environ.get("CONTENT_LENGTH") or 0)
            return json.loads(environ["wsgi.input"].read(ln).decode("utf-8", "replace"))
        except Exception:
            return None

    def app(environ, start_response):
        path = environ.get("PATH_INFO", "/")
        method = environ["REQUEST_METHOD"]
        ctype = environ.get("CONTENT_TYPE", "")
        sess = sessions.get(_sid(environ))

        if path == "/register" and method == "POST":
            d = form(environ)
            u, p = first(d, "username"), first(d, "password")
            if u and p:
                users[u] = {"username": u, "password": p, "role": "user"}
            return respond(start_response, '{"ok":true}', headers=_HDRS, ctype="application/json")

        if path == "/login" and method == "POST":
            d = form(environ)
            u, p = first(d, "username"), first(d, "password")
            user = users.get(u)
            if user and user["password"] == p:
                sid = secrets.token_hex(8)
                sessions[sid] = {"username": u, "role": user["role"]}
                hdrs = _HDRS + [("Set-Cookie", f"connect.sid={sid}; Path=/; HttpOnly")]
                return respond(start_response, '{"ok":true}', headers=hdrs, ctype="application/json")
            return respond(start_response, '{"ok":false}', status="401 Unauthorized",
                           headers=_HDRS, ctype="application/json")

        if path in ("/api/settings", "/settings") and method == "POST":
            if not sess:
                return respond(start_response, '{"error":"auth"}', status="401 Unauthorized",
                               headers=_HDRS, ctype="application/json")
            if "application/json" in ctype:
                obj = body_json(environ)
            else:  # Smesh-style: build JSON from interpolated string fields
                d = form(environ)
                theme, lang = first(d, "theme", "en"), first(d, "language", "en")
                try:
                    obj = json.loads('{"theme": "%s", "language": "%s", "notifications": false}'
                                     % (theme, lang))
                except Exception:
                    obj = None
            if obj is not None:
                detect(obj)
            return respond(start_response, '{"ok":true}', headers=_HDRS, ctype="application/json")

        if path == "/admin":
            if is_admin(sess):
                return respond(start_response, f"<html><body>Admin. Flag: {flag}</body></html>",
                               headers=_HDRS)
            return respond(start_response, "Access Denied", status="403 Forbidden", headers=_HDRS)

        if path == "/dashboard":
            if not sess:
                return respond(start_response, "", status="302 Found",
                               headers=_HDRS + [("Location", "/login")])
            return respond(start_response, "<html><body>dashboard</body></html>", headers=_HDRS)

        return respond(start_response, "<html><body>Smesh-like app. /login /register</body></html>",
                       headers=_HDRS)

    return app
