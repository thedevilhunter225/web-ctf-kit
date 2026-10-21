"""Offline source analysis orchestrator.

Combines archive iteration, line-level static rules, AST-based Python taint
analysis, light JS analysis, Docker/compose parsing, framework identification and
flag extraction into a single :class:`~webctf.core.evidence.Result`.
"""
from __future__ import annotations

from pathlib import Path

from ..core.evidence import Finding, Result
from ..flags.engine import compile_patterns
from ..flags.watch import record_flags
from . import framework
from .archive import iter_sources
from .docker import analyze_compose, analyze_dockerfile
from .js_analysis import analyze_js
from .php_analysis import analyze_php, php_targets
from .python_ast import analyze_python
from .static_rules import COMPILED, WITHHELD

_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".vue")
_PHP_SUFFIXES = (".php", ".phtml", ".php5", ".inc")
_MAX_LINE = 2000


def analyze(path: str, flag_regex: str = "", flag_only: bool = False) -> Result:
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(path)
    patterns = compile_patterns(flag_regex, flag_only)
    result = Result(target=str(src.resolve()), mode="source")
    files: dict[str, str] = {}
    routes: list[str] = []
    count = 0

    for name, body in iter_sources(src):
        count += 1
        result.visited.append(name)
        files[name] = body
        base = name.rsplit("/", 1)[-1].lower()

        _static_rules(name, body, result)
        record_flags(result, body, name, patterns=patterns, origin="source")

        if name.lower().endswith(".py"):
            py_findings, py_routes = analyze_python(name, body)
            for f in py_findings:
                result.add_finding(f)
            routes.extend(py_routes)
        elif name.lower().endswith(_JS_SUFFIXES):
            for f in analyze_js(name, body):
                result.add_finding(f)
        elif name.lower().endswith(_PHP_SUFFIXES):
            for f in analyze_php(name, body):
                result.add_finding(f)
        if base == "dockerfile" or base.endswith(".dockerfile"):
            for f in analyze_dockerfile(name, body):
                result.add_finding(f)
        elif base in ("docker-compose.yml", "docker-compose.yaml", "compose.yml"):
            for f in analyze_compose(name, body):
                result.add_finding(f)

    info = framework.identify(files)
    routes = sorted(set(routes) | set(info["routes"]))
    if info["frameworks"]:
        result.add_finding(Finding(
            "Framework identified", "informational", "(source)",
            ", ".join(info["frameworks"]),
            "Detected application framework(s) from the source.",
            "Prioritise framework-specific bug classes.", origin="source"))
    result.metadata = {
        "files_examined": count,
        "frameworks": info["frameworks"],
        "languages": info["languages"],
        "routes": routes,
        "entrypoints": info["entrypoints"],
        "config_files": info["config_files"],
        "note": "Static findings are leads, not proof; confirm reachability.",
    }
    php = php_targets(files)
    if php["gadgets"] or php["upload_fields"] or php["has_phar_filter"]:
        result.metadata["php"] = php
    return result


def _static_rules(name: str, body: str, result: Result) -> None:
    for line_no, line in enumerate(body.splitlines(), 1):
        stripped = line.strip()
        if not stripped or len(line) > _MAX_LINE:
            continue
        for pattern, title, conf, why, cwe in COMPILED:
            if not pattern.search(line):
                continue
            evidence = stripped[:170]
            if title in WITHHELD:
                evidence = "[value withheld; inspect the source locally]"
            result.add_finding(Finding(
                title, conf, f"{name}:{line_no}", evidence, why,
                "Inspect adjacent code and verify exploitability.",
                origin="source", cwe=cwe))
