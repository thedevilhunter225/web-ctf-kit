"""OS command injection via a safely-emulated shell. TEST FIXTURE ONLY.

A real challenge would do ``os.system("ping " + host)``. To stay safe and
cross-platform, this parses the command with a tiny emulated shell that supports
the separators attackers use plus ``echo`` and ``cat`` — enough to exercise the
scanner's marker detection and the exploit's read-only flag ``cat``.
"""
from __future__ import annotations

import re

from .wsgi_common import first, query, respond

_FLAG_FILES = {"/flag", "/flag.txt", "/app/flag", "/app/flag.txt",
               "flag", "flag.txt", "../flag", "../flag.txt"}
_HOME = '<html><body><a href="/ping?host=127.0.0.1">ping tool</a>'


def make_app(flag: str = "flag{cmdi_exec_demo}"):
    def run(cmd: str) -> str:
        out: list[str] = []
        for part in re.split(r";|\|\||\||&&|\n", cmd):
            part = part.strip()
            m = re.match(r"\$\((.*)\)$", part) or re.match(r"`(.*)`$", part)
            if m:
                part = m.group(1).strip()
            if part.startswith("echo "):
                out.append(part[5:].strip())
            elif part.startswith("cat "):
                for token in part[4:].split():
                    if token in _FLAG_FILES:
                        out.append(flag)
            elif part.startswith("ping"):
                out.append("PING 127.0.0.1: 1 packets transmitted, 1 received")
        return "\n".join(out)

    def app(environ, start_response):
        if environ.get("PATH_INFO", "/") != "/ping":
            return respond(start_response, _HOME + "</body></html>")
        host = first(query(environ), "host", "127.0.0.1")
        output = run("ping -c 1 " + host)  # vulnerable concatenation (emulated)
        return respond(start_response, f"{_HOME}<pre>{output}</pre></body></html>")
    return app


app = make_app()
