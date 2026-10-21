"""Scanner-specific tests: open redirect, CRLF, blind boolean SQLi, disclosure.

Uses a raw http.server handler (not WSGI) so a CRLF header-injection surface can
be reproduced exactly (wsgiref would reject control characters in headers).
"""
import atexit
import sqlite3
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from webctf.core.config import RunConfig
from webctf.core.engine import run

_DB = sqlite3.connect(":memory:", check_same_thread=False)
_DB.execute("CREATE TABLE users(id TEXT, username TEXT)")
_DB.executemany("INSERT INTO users VALUES(?,?)", [("1", "alice"), ("2", "bob")])
_DB.commit()
_DB_LOCK = threading.Lock()
atexit.register(_DB.close)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, status=200, headers=None, ctype="text/html"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        for k, v in (headers or []):
            self.send_header(k, v)  # permissive: enables the CRLF test
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parts = urlsplit(self.path)
        path, q = parts.path, parse_qs(parts.query)
        if path == "/redir":
            nxt = q.get("next", [""])[0]
            self.send_response(302)
            self.send_header("Location", nxt)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/crlf":
            self._send("ok", headers=[("X-Echo", q.get("x", [""])[0])])
            return
        if path == "/user":
            uid = q.get("id", ["1"])[0]
            try:
                with _DB_LOCK:
                    rows = _DB.execute("SELECT username FROM users WHERE id='%s'" % uid).fetchall()
            except Exception:
                rows = []  # blind: errors are hidden
            self._send("Welcome " + rows[0][0] if rows else "Invalid credentials")
            return
        if path == "/.git/HEAD":
            self._send("ref: refs/heads/master\n", ctype="text/plain")
            return
        if path == "/ssrf":
            url = q.get("url", [""])[0]
            body = "no fetch"
            if url.startswith("http://127.0.0.1"):
                try:
                    body = "FETCHED:" + urllib.request.urlopen(url, timeout=3).read(400).decode("utf-8", "replace")
                except Exception:
                    body = "fetch error"
            self._send(body)
            return
        if path == "/":
            self._send('<html><body><a href="/user?id=1">u</a></body></html>')
            return
        self._send("not found", status=404)


class ScannerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}/"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def _run(self, start, only, max_tests=60):
        return run(self.base + start, RunConfig(active=True, delay=0, enum_paths=False,
                                                max_pages=4, max_tests=max_tests, only=only))

    def test_open_redirect(self):
        res = self._run("redir?next=seed", ("redirect",))
        self.assertTrue(any(f.category == "Open redirect" for f in res.findings))

    def test_crlf_header_injection(self):
        res = self._run("crlf?x=1", ("crlf",))
        self.assertTrue(any(f.category == "CRLF / HTTP header injection" for f in res.findings))

    def test_boolean_blind_sqli(self):
        res = self._run("user?id=1", ("sqli",), max_tests=40)
        self.assertTrue(any("boolean" in f.category.lower() for f in res.findings),
                        f"boolean SQLi not detected; got {[f.category for f in res.findings]}")

    def test_disclosure_git(self):
        res = run(self.base, RunConfig(active=True, delay=0, enum_paths=False,
                                       max_pages=2, max_tests=40, only=("disclosure",)))
        self.assertTrue(any(f.category == "Exposed .git repository" for f in res.findings))

    def test_ssrf_hypothesis_experimental(self):
        res = self._run("ssrf?url=x", ("ssrf",))
        self.assertTrue(any(h.category == "SSRF" or h.scanner == "ssrf" for h in res.hypotheses))


if __name__ == "__main__":
    unittest.main()
