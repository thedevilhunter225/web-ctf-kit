"""Core tests: scoped transport, crawler, reporting and the CLI.

All network I/O is against a local 127.0.0.1 server; no internet host is used.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webctf.cli import main  # noqa: E402
from webctf.core.config import RunConfig  # noqa: E402
from webctf.core.engine import run  # noqa: E402
from webctf.core.evidence import Finding, Flag, Result  # noqa: E402
from webctf.core.target import Transport, in_scope, normalize, origin  # noqa: E402
from webctf.reporting import as_markdown, save_report  # noqa: E402
from webctf.browser.bot import build_visit_url, submit_report  # noqa: E402
from fixtures.server import ServedApp  # noqa: E402
from fixtures import admin_bot, ssti_eval  # noqa: E402


def demo_app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    if path == "/redirect-out":
        start_response("302 Found", [("Location", "https://example.invalid/nope"),
                                     ("Content-Length", "0")])
        return [b""]
    if path == "/page2":
        body = b"<html><body>page two</body></html>"
    elif path == "/":
        body = (b'<html><body><form method="POST" action="/post">'
                b'<input name="data"></form>flag{crawl_me}'
                b'<a href="/page2">p2</a>'
                b'<a href="https://example.invalid/out">ext</a></body></html>')
    else:
        start_response("404 Not Found", [("Content-Length", "0")])
        return [b""]
    start_response("200 OK", [("Content-Type", "text/html"), ("Content-Length", str(len(body)))])
    return [body]


def capture(argv) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, buf.getvalue()


class TransportTests(unittest.TestCase):
    def test_origin_and_scope(self):
        self.assertEqual(origin("http://a.test:8080/x")[1:], ("a.test", 8080))
        self.assertTrue(in_scope("http://h:1/a", "http://h:1/b"))
        self.assertFalse(in_scope("http://h:1/a", "http://h:2/a"))
        self.assertFalse(in_scope("http://h:1/a", "http://other/a"))

    def test_reject_credentials_and_scheme(self):
        with self.assertRaises(ValueError):
            origin("http://user:pass@h/")
        with self.assertRaises(ValueError):
            origin("ftp://h/")

    def test_out_of_scope_request_blocked(self):
        with ServedApp(demo_app) as s:
            t = Transport(s.url, delay=0)
            with self.assertRaises(ValueError):
                t.request("https://example.invalid/")

    def test_external_redirect_not_followed(self):
        with ServedApp(demo_app) as s:
            t = Transport(s.url, delay=0)
            resp = t.request("/redirect-out")
            self.assertEqual(resp.status, 302)
            self.assertIn("example.invalid", resp.header("location"))

    def test_header_injection_rejected(self):
        with ServedApp(demo_app) as s:
            with self.assertRaises(ValueError):
                Transport(s.url, headers={"X-Bad": "a\r\nInjected: 1"}, delay=0).request("/")


class CrawlerTests(unittest.TestCase):
    def test_passive_crawl_discovers_form_and_flag(self):
        with ServedApp(demo_app) as s:
            result = run(s.url, RunConfig(active=False, delay=0, max_pages=5))
        self.assertTrue(any(p.name == "data" and p.method == "POST" for p in result.parameters))
        self.assertTrue(any(fl.value == "flag{crawl_me}" for fl in result.flags))
        self.assertTrue(all("example.invalid" not in v for v in result.visited))
        self.assertEqual(result.metadata["probes_sent"], 0)


class ReportingTests(unittest.TestCase):
    def _demo_result(self) -> Result:
        r = Result(target="http://x/", mode="solve")
        r.add_finding(Finding("SSTI", "confirmed", "GET / ?x=", "flag read",
                              "evidence", "next", origin="exploit"))
        r.add_flag(Flag("flag{report}", "GET / ?x=", "ssti", verified=True))
        r.requests = 3
        return r

    def test_save_report(self):
        result = self._demo_result()
        with tempfile.TemporaryDirectory() as out:
            j, m = save_report(result, out)
            self.assertTrue(j.exists() and m.exists())
            data = json.loads(j.read_text(encoding="utf-8"))
            self.assertEqual(len(data["findings"]), 1)
            self.assertEqual(data["flags"][0]["value"], "flag{report}")

    def test_markdown_contains_flag(self):
        md = as_markdown(self._demo_result())
        self.assertIn("# Web CTF Kit report", md)
        self.assertIn("flag{report}", md)
        self.assertIn("VERIFIED", md)


class CLITests(unittest.TestCase):
    def test_plugins_and_doctor(self):
        code, out = capture(["plugins"])
        self.assertEqual(code, 0)
        self.assertIn("ssti", out)
        code, out = capture(["doctor"])
        self.assertEqual(code, 0)
        self.assertIn("No AI", out)

    def test_analyze_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / "src.zip"
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("app.py", "from flask import request\n"
                            "x = request.args.get('n')\n"
                            "import os\nos.system('ls '+x)\n")
            code, out = capture(["analyze", "--source", str(z), "--json"])
            self.assertEqual(code, 0)
            data = json.loads(out)
            self.assertTrue(any("command injection" in f["category"] for f in data["findings"]))

    def test_active_requires_ack(self):
        with ServedApp(ssti_eval.make_app()) as s:
            code, _ = capture(["scan", "--url", s.url])
            self.assertEqual(code, 2)  # refused without --ack-authorized

    def test_solve_cli_extracts_flag(self):
        with ServedApp(ssti_eval.make_app("flag{cli_solve}")) as s:
            code, out = capture(["solve", "--url", s.url, "--ack-authorized",
                                 "--no-paths", "--delay", "0", "--max-tests", "80", "--json"])
            self.assertEqual(code, 0)
            data = json.loads(out)
            self.assertTrue(any(f["value"] == "flag{cli_solve}" and f["verified"]
                                for f in data["flags"]))

    def test_report_from_saved_json(self):
        with tempfile.TemporaryDirectory() as out:
            result = Result(target="http://x/", mode="solve")
            result.add_flag(Flag("flag{saved}", "x", "ssti", verified=True))
            save_report(result, out)
            code, text = capture(["report", "--input", str(Path(out) / "findings.json")])
            self.assertEqual(code, 0)
            self.assertIn("flag{saved}", text)

    def test_custom_flag_regex(self):
        def app(environ, start_response):
            body = b"here is SECRET-7f3a-END in the page"
            start_response("200 OK", [("Content-Type", "text/html"),
                                      ("Content-Length", str(len(body)))])
            return [body]
        with ServedApp(app) as s:
            code, out = capture(["recon", "--url", s.url, "--delay", "0",
                                 "--flag-regex", r"SECRET-[0-9a-f]+-END", "--json"])
            self.assertEqual(code, 0)
            data = json.loads(out)
            self.assertTrue(any(f["value"] == "SECRET-7f3a-END" for f in data["flags"]))


class BotTests(unittest.TestCase):
    def test_build_visit_url(self):
        url = build_visit_url(bot_base="http://127.0.0.1:8000/", inject_param="q", payload="<b>x</b>")
        self.assertIn("q=%3Cb%3Ex%3C%2Fb%3E", url)
        with self.assertRaises(ValueError):
            build_visit_url(visit_url="http://a/", bot_base="http://b/")

    def test_submit_report_scope(self):
        with ServedApp(admin_bot.make_app()) as s:
            reply = submit_report(s.url, s.url + "flagbox", report_field="url")
            self.assertEqual(reply.status, 200)
            self.assertIn("visited", reply.text)
            # The *report endpoint* must be same-origin; an off-origin one is refused.
            with self.assertRaises(ValueError):
                submit_report(s.url, s.url, report_path="http://evil.invalid/report")


class JWTTests(unittest.TestCase):
    def test_decode_forge_crack(self):
        from webctf.exploits import jwt_forge
        token = jwt_forge.forge_hs256(
            "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.x", "secret", {"user": "guest"})
        self.assertEqual(jwt_forge.crack_hs256(token), "secret")
        none_tok = jwt_forge.forge_none(token, {"user": "admin"})
        self.assertTrue(none_tok.endswith("."))
        self.assertEqual(jwt_forge.decode(none_tok)["payload"]["user"], "admin")


if __name__ == "__main__":
    unittest.main()
