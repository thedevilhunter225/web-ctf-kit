"""Path traversal / LFI file viewer (emulated FS). TEST FIXTURE ONLY.

Emulates a file reader so the /etc/passwd confirmation and flag-path reads work
identically on Linux, macOS and Windows. The requested path is URL-decoded and
normalised (so ``../`` and ``%2f`` both work), then matched by suffix.
"""
from __future__ import annotations

import posixpath
from urllib.parse import unquote

from .wsgi_common import first, query, respond

_PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
           "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")
_HOME = '<html><body><a href="/view?file=welcome.txt">welcome.txt</a></body></html>'


def make_app(flag: str = "flag{lfi_traversal_demo}"):
    def app(environ, start_response):
        if environ.get("PATH_INFO", "/") != "/view":
            return respond(start_response, _HOME)
        raw = first(query(environ), "file") or first(query(environ), "page")
        norm = posixpath.normpath(unquote(raw).replace("\\", "/"))
        tail = norm.rstrip("/").split("/")[-1]
        if norm.endswith("etc/passwd"):
            return respond(start_response, _PASSWD, ctype="text/plain; charset=utf-8")
        if tail in ("flag", "flag.txt"):
            return respond(start_response, flag + "\n", ctype="text/plain; charset=utf-8")
        return respond(start_response, f"<html><body>Viewing {norm}: not found</body></html>",
                       status="404 Not Found")
    return app


app = make_app()
