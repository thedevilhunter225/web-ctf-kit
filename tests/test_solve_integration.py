"""End-to-end solve tests against local, self-contained vulnerable fixtures.

Every server is bound to 127.0.0.1 on an ephemeral port; no internet host is ever
contacted. These tests assert *actual flag extraction*, not just vulnerability
alerts, for the core exploit primitives.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webctf.core.config import RunConfig  # noqa: E402
from webctf.core.engine import run  # noqa: E402
from fixtures.server import ServedApp  # noqa: E402
from fixtures import (  # noqa: E402
    admin_bot, cmdi_ping, flask_ssti, lfi_viewer, sqli_login, ssti_eval, xss_blacklist,
)

CFG = dict(active=True, solve=True, max_pages=12, max_tests=200,
           delay=0, enum_paths=False, timeout=6)


def solve(app, start_path=""):
    with ServedApp(app) as s:
        return run(s.url + start_path, RunConfig(**CFG))


class SolveIntegration(unittest.TestCase):
    def _assert_flag(self, result, expected):
        best = result.best_flag()
        self.assertIsNotNone(best, "no flag recovered")
        self.assertTrue(best.verified, f"flag not verified: {best}")
        self.assertEqual(best.value, expected)
        # A verified flag must be backed by a 'confirmed' finding.
        self.assertTrue(any(f.confidence == "confirmed" for f in result.findings))
        # No out-of-scope requests should have leaked.
        self.assertTrue(all("example.invalid" not in v for v in result.visited))

    def test_ssti_stdlib_flag(self):
        result = solve(ssti_eval.make_app("flag{ssti_it1}"))
        self._assert_flag(result, "flag{ssti_it1}")
        self.assertTrue(any(f.category == "Server-side template injection"
                            for f in result.findings))

    @unittest.skipIf(flask_ssti.make_app() is None, "Flask/Jinja2 not installed")
    def test_ssti_real_jinja2_flag(self):
        result = solve(flask_ssti.make_app("flag{jinja_it2}"))
        self._assert_flag(result, "flag{jinja_it2}")

    def test_sqli_union_flag(self):
        result = solve(sqli_login.make_app("flag{sqli_it3}"))
        self._assert_flag(result, "flag{sqli_it3}")
        self.assertTrue(any("SQL injection" in f.category for f in result.findings))

    def test_lfi_traversal_flag(self):
        result = solve(lfi_viewer.make_app("flag{lfi_it4}"))
        self._assert_flag(result, "flag{lfi_it4}")
        self.assertTrue(any(f.category == "Path traversal / local file read"
                            for f in result.findings))

    def test_cmdi_flag(self):
        result = solve(cmdi_ping.make_app("flag{cmdi_it5}"))
        self._assert_flag(result, "flag{cmdi_it5}")
        self.assertTrue(any(f.category == "OS command injection" for f in result.findings))

    def test_xss_blacklist_bypass_detected(self):
        result = solve(xss_blacklist.make_app())
        xss = [f for f in result.findings if "XSS" in f.category]
        self.assertTrue(xss, "reflected XSS not detected")
        # The simple tags are blacklisted; an executable handler must bypass it.
        self.assertTrue(any(f.category == "Reflected XSS (executable handler survived)"
                            for f in xss),
                        f"executable bypass not reported; got {[f.category for f in xss]}")

    def test_admin_bot_reflects_and_report_accepts(self):
        from webctf.browser.bot import submit_report
        with ServedApp(admin_bot.make_app("flag{bot_it6}")) as s:
            result = run(s.url, RunConfig(**CFG))
            # The bot's report endpoint accepts a same-origin visit URL.
            reply = submit_report(s.url, s.url + "flagbox", report_field="url")
            self.assertEqual(reply.status, 200)
            self.assertIn("visited", reply.text)
        self.assertTrue(any("XSS" in f.category for f in result.findings))

    def test_budget_is_respected(self):
        with ServedApp(sqli_login.make_app()) as s:
            result = run(s.url, RunConfig(active=True, solve=True, max_tests=15,
                                          delay=0, enum_paths=False, max_pages=5))
        self.assertLessEqual(result.metadata["probes_sent"], 15)

    def test_passive_recon_sends_no_probes(self):
        with ServedApp(sqli_login.make_app()) as s:
            result = run(s.url, RunConfig(active=False, delay=0, max_pages=5))
        self.assertEqual(result.metadata["probes_sent"], 0)
        self.assertEqual(result.mode, "recon")
        # No exploitation findings in passive mode.
        self.assertFalse(any(f.confidence == "confirmed" for f in result.findings))


if __name__ == "__main__":
    unittest.main()
