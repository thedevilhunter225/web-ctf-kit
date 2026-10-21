"""Technology fingerprinting from headers, cookies and body markers.

The output steers the planner: a Flask/Jinja2 stack raises the priority of SSTI
probes, a PHP stack raises LFI/wrapper probes, an Express stack raises prototype
pollution and NoSQL probes, and so on. Detection is signature based and
conservative; an unknown stack simply yields fewer hints, never a crash.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..core.target import Response

# cookie-name -> (framework, language)
_COOKIE_SIGNS = {
    "phpsessid": ("PHP", "php"),
    "jsessionid": ("Java/Servlet", "java"),
    "connect.sid": ("Express/Node.js", "javascript"),
    "laravel_session": ("Laravel", "php"),
    "ci_session": ("CodeIgniter", "php"),
    "csrftoken": ("Django", "python"),
    "sessionid": ("Django", "python"),
    "_rails_session": ("Rails", "ruby"),
    "sails.sid": ("Sails.js", "javascript"),
}

# header substring -> (framework, language)
_POWERED = {
    "express": ("Express/Node.js", "javascript"),
    "php": ("PHP", "php"),
    "asp.net": ("ASP.NET", "csharp"),
    "next.js": ("Next.js", "javascript"),
    "servlet": ("Java/Servlet", "java"),
}

# body marker regex -> (framework, language, note)
_BODY = [
    (re.compile(r"Werkzeug Debugger|werkzeug/\d|The Werkzeug", re.I), "Flask/Werkzeug", "python",
     "Werkzeug debugger/banner visible"),
    (re.compile(r"jinja2\.exceptions|TemplateSyntaxError|TemplateNotFound", re.I), "Jinja2", "python",
     "Jinja2 template error surfaced"),
    (re.compile(r"Django Version|You're seeing this error because you have <code>DEBUG", re.I),
     "Django", "python", "Django debug page visible"),
    (re.compile(r"Traceback \(most recent call last\)", re.I), "Python", "python",
     "Python traceback surfaced"),
    (re.compile(r"<b>(?:Warning|Fatal error|Notice)</b>:.*on line <b>\d+", re.I | re.S), "PHP", "php",
     "PHP error with file/line surfaced"),
    (re.compile(r"Cannot GET /|Cannot POST /", re.I), "Express/Node.js", "javascript",
     "Express default 404 phrasing"),
    (re.compile(r"Ruby on Rails|Rails\.application", re.I), "Rails", "ruby", "Rails marker"),
    (re.compile(r"__NEXT_DATA__|/_next/static", re.I), "Next.js", "javascript", "Next.js markers"),
    (re.compile(r"ThreadingHTTPServer|BaseHTTP/|SimpleHTTP", re.I), "Python http.server", "python",
     "Python stdlib HTTP server banner"),
]

_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


@dataclass
class Fingerprint:
    server: str = ""
    powered_by: str = ""
    frameworks: set[str] = field(default_factory=set)
    languages: set[str] = field(default_factory=set)
    cookies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "server": self.server,
            "powered_by": self.powered_by,
            "frameworks": sorted(self.frameworks),
            "languages": sorted(self.languages),
            "cookies": self.cookies,
            "notes": self.notes,
            "headers": self.headers,
        }

    def summary(self) -> str:
        bits = sorted(self.frameworks) or sorted(self.languages)
        label = ", ".join(bits) if bits else (self.server or "unknown stack")
        return label


_INTERESTING_HEADERS = (
    "server", "x-powered-by", "x-aspnet-version", "x-generator", "via",
    "x-runtime", "content-security-policy", "x-frame-options", "set-cookie",
)


def fingerprint(*responses: Response) -> Fingerprint:
    """Fuse signals from one or more responses into a :class:`Fingerprint`."""
    fp = Fingerprint()
    for resp in responses:
        if resp is None:
            continue
        server = resp.header("server")
        if server and not fp.server:
            fp.server = server
        powered = resp.header("x-powered-by")
        if powered and not fp.powered_by:
            fp.powered_by = powered
        for name in _INTERESTING_HEADERS:
            value = resp.header(name)
            if value and name not in fp.headers:
                fp.headers[name] = value[:300]

        blob = f"{server} {powered}".lower()
        for needle, (fw, lang) in _POWERED.items():
            if needle in blob:
                fp.frameworks.add(fw)
                fp.languages.add(lang)
        if "werkzeug" in blob:
            fp.frameworks.add("Flask/Werkzeug")
            fp.languages.add("python")
        elif "python" in blob or "cpython" in blob or "wsgiserver" in blob:
            # A Python web server, but not necessarily Flask — don't overclaim.
            fp.languages.add("python")
        if "nginx" in blob or "apache" in blob:
            pass  # web server, not an app framework

        set_cookie = resp.header("set-cookie").lower()
        for cname, (fw, lang) in _COOKIE_SIGNS.items():
            if cname in set_cookie:
                fp.frameworks.add(fw)
                fp.languages.add(lang)
                if cname not in fp.cookies:
                    fp.cookies.append(cname)
        # Flask signed-session cookie heuristic: "session=eyJ" / "session=."
        if re.search(r"session=(?:ey[A-Za-z0-9]|\.|[A-Za-z0-9_-]+\.)", set_cookie):
            fp.frameworks.add("Flask/Werkzeug")
            fp.languages.add("python")
            if "flask-session" not in fp.cookies:
                fp.cookies.append("flask-session")

        text = resp.text or ""
        for pattern, fw, lang, note in _BODY:
            if pattern.search(text):
                fp.frameworks.add(fw)
                fp.languages.add(lang)
                if note not in fp.notes:
                    fp.notes.append(note)
        gen = _GENERATOR.search(text)
        if gen:
            note = f"generator meta: {gen.group(1)[:80]}"
            if note not in fp.notes:
                fp.notes.append(note)
    return fp
