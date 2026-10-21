"""Realistic Flask + Jinja2 SSTI. TEST FIXTURE ONLY.

Only usable when Flask/Jinja2 are installed (``make_app`` returns None otherwise).
Unlike the stdlib SSTI fixture, this runs a *real* Jinja2 environment, so the
actual ``cycler.__init__.__globals__`` gadget chain is validated against it.
"""
from __future__ import annotations


def make_app(flag: str = "flag{jinja2_ssti_real}"):
    try:
        from flask import Flask, request, render_template_string
    except Exception:
        return None
    import os

    os.environ["FLAG"] = flag
    app = Flask(__name__)

    @app.route("/")
    def index():
        name = request.args.get("name", "guest")
        # A link advertises the parameter (so the crawler discovers it), then the
        # value is concatenated into the template source: classic SSTI.
        link = '<a href="/?name=guest">home</a>'
        return render_template_string(link + "<h1>Hello " + name + "</h1>")

    return app
