"""PHAR-deserialization upload challenge (four0four-like). TEST FIXTURE ONLY.

Python has no phar engine, so this emulates the *observable* PHP behaviour: a GIF
upload + a user-controlled ``scheme`` concatenated into a file op, guarded by a
case-sensitive ``phar://`` blacklist. When the scheme bypasses the blacklist and
resolves to ``phar://``, it emulates phar deserialization by scanning the uploaded
bytes for a serialized POP gadget whose callable is a command function and whose
argument reads the flag — then returns the flag, as real PHP would echo it.
"""
from __future__ import annotations

import re

from .wsgi_common import respond

_FORM = ('<!DOCTYPE html><html><body><h1>four0four</h1>'
         '<form action="index.php" method="post" enctype="multipart/form-data">'
         '<input type="file" name="gifimage">'
         '<input type="hidden" name="scheme" value="file://">'
         '<input type="submit" name="submit" value="Submit"></form>')

_GADGET = re.compile(rb'O:\d+:"[^"]+":\d+:\{.*\}', re.S)
_RUNNERS = (b'"system"', b'"passthru"', b'"exec"', b'"shell_exec"', b'"popen"', b'"proc_open"')
_BLACKLIST = re.compile(r"phar://")  # case-sensitive, like preg_match('/phar:\/\//', ...)


def _parse_multipart(environ):
    ctype = environ.get("CONTENT_TYPE", "")
    if "multipart/form-data" not in ctype or "boundary=" not in ctype:
        return {}, {}
    boundary = ctype.split("boundary=", 1)[1].strip().strip('"')
    length = int(environ.get("CONTENT_LENGTH") or 0)
    body = environ["wsgi.input"].read(length) if length else b""
    fields, files = {}, {}
    for part in body.split(("--" + boundary).encode()):
        part = part.strip(b"\r\n")
        if not part or part == b"--" or b"\r\n\r\n" not in part:
            continue
        head, _, content = part.partition(b"\r\n\r\n")
        head_s = head.decode("latin-1", "replace")
        nm = re.search(r'name="([^"]*)"', head_s)
        if not nm:
            continue
        content = content.rstrip(b"\r\n")
        fn = re.search(r'filename="([^"]*)"', head_s)
        if fn:
            files[nm.group(1)] = (fn.group(1), content)
        else:
            fields[nm.group(1)] = content.decode("latin-1", "replace")
    return fields, files


def _gadget_fires(content: bytes) -> bool:
    m = _GADGET.search(content)
    if not m:
        return False
    blob = m.group(0)
    has_runner = any(r in blob for r in _RUNNERS)
    reads_flag = b"flag" in blob or b"cat " in blob
    return has_runner and reads_flag


def make_app(flag: str = "ARENA{emulated_phar_rce}"):
    def app(environ, start_response):
        if environ["REQUEST_METHOD"] != "POST":
            return respond(start_response, _FORM + "</body></html>")
        fields, files = _parse_multipart(environ)
        up = next(iter(files.values()), None)
        scheme = fields.get("scheme") or "file://"
        if up is None:
            return respond(start_response, _FORM + "no file</body></html>")
        fname, content = up
        is_gif = content[:6] in (b"GIF89a", b"GIF87a")
        if not (is_gif and fname.lower().endswith(".gif")):
            return respond(start_response, _FORM + "404 NOT GIF!</body></html>")
        if _BLACKLIST.search(scheme):           # case-sensitive: blocks lowercase phar://
            return respond(start_response, _FORM + "No phar allowed</body></html>")
        if "phar://" in scheme.lower():         # strtolower re-enables the wrapper
            if _gadget_fires(content):
                return respond(start_response, _FORM + flag + "</body></html>")
        return respond(start_response, _FORM + "File Submitted</body></html>")
    return app
