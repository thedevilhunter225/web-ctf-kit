"""TUI tests driven by scripted stdin (non-TTY, so no animation/clears)."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webctf.tui import run_tui  # noqa: E402
from fixtures.server import ServedApp  # noqa: E402
from fixtures import ssti_eval  # noqa: E402


def drive(lines):
    """Run the TUI with *lines* fed on stdin; return (exit_code, stdout)."""
    buf = io.StringIO()
    old = sys.stdin
    sys.stdin = io.StringIO("\n".join(lines) + "\n")
    try:
        with contextlib.redirect_stdout(buf):
            code = run_tui(no_color=True)
    finally:
        sys.stdin = old
    return code, buf.getvalue()


class TUITests(unittest.TestCase):
    def test_quit(self):
        code, _ = drive(["q"])
        self.assertEqual(code, 0)

    def test_menu_eof_quits(self):
        code, _ = drive([])  # empty stdin -> EOF -> clean quit
        self.assertEqual(code, 0)

    def test_analyze_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / "c.zip"
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("notes.txt", "secret: flag{tui_analyze}")
            code, out = drive(["4", str(z), "", "n", "", "q"])
        self.assertEqual(code, 0)
        self.assertIn("flag{tui_analyze}", out)

    def test_scan_requires_authorization(self):
        code, out = drive(["2", "http://127.0.0.1:1/", "n", "", "q"])
        self.assertEqual(code, 0)
        self.assertIn("Authorization not confirmed", out)

    def test_solve_flow_extracts_flag(self):
        with ServedApp(ssti_eval.make_app("flag{tui_solve}")) as s:
            lines = ["1", s.url, "",          # solve, url, no source
                     "y",                      # authorized
                     "y", "", "", "0", "", "", "", "", "n",  # advanced: delay=0, enum=n
                     "n", "",                  # don't save, pause
                     "q"]
            code, out = drive(lines)
        self.assertEqual(code, 0)
        self.assertIn("flag{tui_solve}", out)
        self.assertIn("FLAG:", out)


if __name__ == "__main__":
    unittest.main()
