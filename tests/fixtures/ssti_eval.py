"""SSTI via a toy ``{{ expr }}`` evaluator (stdlib, no Jinja2). TEST FIXTURE ONLY.

Emulates a template engine that evaluates ``{{ ... }}`` as a Python expression,
which is exactly what makes real SSTI exploitable. The flag is exposed through the
process environment (as a container deployment often does), reachable by the
generic ``{{ __import__('os').environ... }}`` gadget.
"""
from __future__ import annotations

import os
import re

from .wsgi_common import first, form, query, respond

_EXPR = re.compile(r"{{(.*?)}}", re.S)
_NS = {"__builtins__": {"__import__": __import__, "str": str, "range": range}}


def make_app(flag: str = "flag{ssti_stdlib_demo}"):
    os.environ["FLAG"] = flag

    def render(tpl: str) -> str:
        def repl(m):
            try:
                return str(eval(m.group(1), {k: v for k, v in _NS.items()}))  # noqa: S307 (fixture)
            except Exception as exc:  # surface nothing sensitive
                return "{{err:%s}}" % type(exc).__name__
        return _EXPR.sub(repl, tpl)

    def app(environ, start_response):
        data = query(environ)
        if environ["REQUEST_METHOD"] == "POST":
            data.update(form(environ))
        tpl = first(data, "tpl") or first(data, "name") or "world"
        page = ('<html><body><form><input name="tpl"></form>'
                f'<p>Preview: {render(tpl)}</p></body></html>')
        return respond(start_response, page)
    return app
