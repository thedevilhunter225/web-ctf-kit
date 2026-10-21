"""Offline source-analysis tests (AST taint, static rules, archives, docker)."""
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from webctf.analyzers import analyze
from webctf.analyzers.python_ast import analyze_python

VULN_APP = '''
from flask import Flask, request, render_template_string
import os, sqlite3
app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name")
    tpl = "<h1>Hello " + name + "</h1>"
    return render_template_string(tpl)

@app.route("/ping", methods=["POST"])
def ping():
    host = request.form["host"]
    return os.popen("ping " + host).read()

@app.route("/user")
def user():
    uid = request.args.get("id")
    cur = sqlite3.connect("x").cursor()
    cur.execute(f"SELECT * FROM users WHERE id={uid}")
    return "ok"

@app.route("/safe")
def safe():
    x = os.environ.get("HOME")
    return os.popen("ls " + x).read()
'''


class ASTTests(unittest.TestCase):
    def test_taint_source_to_sink(self):
        findings, routes = analyze_python("app.py", VULN_APP)
        cats = {f.category for f in findings}
        self.assertTrue(any("SSTI" in c for c in cats))
        self.assertTrue(any("SQL injection" in c for c in cats))
        self.assertTrue(any("command injection" in c for c in cats))

    def test_routes_extracted(self):
        _, routes = analyze_python("app.py", VULN_APP)
        self.assertIn("GET /greet", routes)
        self.assertIn("POST /ping", routes)

    def test_env_source_is_not_tainted(self):
        # os.environ is not a request source, so the /safe `ls` command (built
        # from an env var) must NOT be reported as a taint finding.
        findings, _ = analyze_python("app.py", VULN_APP)
        self.assertFalse(any('"ls "' in f.evidence for f in findings),
                         "env-sourced command must not be reported as taint")


class SourceScanTests(unittest.TestCase):
    def test_zip_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "dist.zip"
            with zipfile.ZipFile(src, "w") as z:
                z.writestr("dist/app.py", VULN_APP)
                z.writestr("dist/templates/index.html", "{{ output|safe }}")
                z.writestr("dist/Dockerfile", "FROM python:3.11\nENV FLAG=flag{in_env}\nEXPOSE 5000")
                z.writestr("dist/docker-compose.yml",
                           "version: '3'\nservices:\n  web:\n    environment:\n      FLAG: flag{compose}")
            result = analyze(str(src))
        cats = {f.category for f in result.findings}
        self.assertIn("HTML autoescape bypass", cats)
        self.assertTrue(any("SSTI" in c for c in cats))
        self.assertIn("Flask", result.metadata["frameworks"])
        self.assertTrue(any("Docker ENV" in c for c in cats))
        # Secret values from Docker must be withheld.
        docker_finding = next(f for f in result.findings if "Docker ENV" in f.category)
        self.assertNotIn("flag{in_env}", docker_finding.evidence)

    def test_tar_gz_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src.tar.gz"
            inner = Path(tmp) / "app.py"
            inner.write_text(VULN_APP, encoding="utf-8")
            with tarfile.open(src, "w:gz") as t:
                t.add(inner, arcname="app.py")
            result = analyze(str(src))
        self.assertTrue(any("SQL injection" in f.category for f in result.findings))

    def test_flag_in_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "notes.txt"
            f.write_text("the flag is flag{found_in_source}", encoding="utf-8")
            result = analyze(str(f))
        self.assertTrue(any(fl.value == "flag{found_in_source}" for fl in result.flags))

    def test_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            analyze("does-not-exist-xyz")

    def test_prototype_pollution_merge_detected(self):
        # Mirrors the Smesh (PCC 2025) pattern: JSON string interpolation + a
        # recursive key-copying merge with no __proto__ guard.
        js = (
            "function merge(target, source) {\n"
            "  for (let key in source) {\n"
            "    if (typeof source[key] === 'object') { merge(target[key], source[key]); }\n"
            "    else { target[key] = source[key]; }\n"
            "  }\n"
            "}\n"
            "const cfg = JSON.parse(`{\"theme\": \"${req.body.theme}\"}`);\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "app.js"
            p.write_text(js, encoding="utf-8")
            result = analyze(str(p))
        cats = {f.category for f in result.findings}
        self.assertIn("Unsafe recursive merge (prototype pollution)", cats)
        self.assertIn("JSON built from string interpolation", cats)

    def test_safe_merge_not_flagged(self):
        js = ("function merge(t, s) {\n"
              "  for (let k in s) { if (Object.prototype.hasOwnProperty.call(s,k)) t[k]=s[k]; }\n"
              "}\n")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "safe.js"
            p.write_text(js, encoding="utf-8")
            result = analyze(str(p))
        self.assertFalse(any("prototype pollution" in f.category.lower()
                             for f in result.findings))


if __name__ == "__main__":
    unittest.main()
