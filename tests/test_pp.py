"""Tests for the active prototype-pollution -> privilege-escalation auto-exploit."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webctf.core.config import RunConfig  # noqa: E402
from webctf.core.engine import run  # noqa: E402
from webctf.core.evidence import Finding, Result  # noqa: E402
from webctf.exploits.proto_pollute import _should_run  # noqa: E402
from fixtures.server import ServedApp  # noqa: E402
from fixtures import pp_privesc, ssti_eval  # noqa: E402


class _Ctx:
    def __init__(self, result):
        self.result = result


class GatingTests(unittest.TestCase):
    def test_runs_for_js_stack(self):
        r = Result(target="http://x/", mode="solve")
        r.metadata["frameworks"] = ["Express/Node.js"]
        self.assertTrue(_should_run(_Ctx(r)))

    def test_runs_on_source_evidence(self):
        r = Result(target="http://x/", mode="solve")
        r.metadata["frameworks"] = ["unknown"]
        r.add_finding(Finding("Unsafe recursive merge (prototype pollution)", "high",
                              "app.js:1", "for..in", "why", "next", origin="source"))
        self.assertTrue(_should_run(_Ctx(r)))

    def test_skips_non_js_without_evidence(self):
        r = Result(target="http://x/", mode="solve")
        r.metadata["frameworks"] = ["PHP", "Flask/Werkzeug"]
        self.assertFalse(_should_run(_Ctx(r)))


class PPExploitTests(unittest.TestCase):
    def test_blackbox_auto_solve(self):
        with ServedApp(pp_privesc.make_app("flag{pp_auto}")) as s:
            res = run(s.url, RunConfig(active=True, solve=True, delay=0,
                                       enum_paths=False, max_pages=6, max_tests=250))
        best = res.best_flag()
        self.assertIsNotNone(best, "no flag recovered")
        self.assertTrue(best.verified)
        self.assertEqual(best.value, "flag{pp_auto}")
        self.assertTrue(any(f.category == "Prototype pollution -> privilege escalation"
                            for f in res.findings))

    def test_not_run_without_solve(self):
        # Active scan (no --solve) must not perform the intrusive escalation.
        with ServedApp(pp_privesc.make_app("flag{should_not_leak}")) as s:
            res = run(s.url, RunConfig(active=True, solve=False, delay=0,
                                       enum_paths=False, max_pages=4, max_tests=80))
        self.assertFalse(any(f.category == "Prototype pollution -> privilege escalation"
                             for f in res.findings))
        self.assertFalse(any(f.value == "flag{should_not_leak}" for f in res.flags))

    def test_skips_python_target(self):
        # A Python SSTI app must be solved by SSTI, not falsely attributed to PP.
        with ServedApp(ssti_eval.make_app("flag{py_ssti}")) as s:
            res = run(s.url, RunConfig(active=True, solve=True, delay=0,
                                       enum_paths=False, max_pages=3, max_tests=120))
        self.assertFalse(any("prototype pollution" in f.category.lower()
                             for f in res.findings))


if __name__ == "__main__":
    unittest.main()
