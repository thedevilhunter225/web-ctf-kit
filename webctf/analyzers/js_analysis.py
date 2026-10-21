"""Light JavaScript/TypeScript sink detection (regex-based).

A full JS AST would need a third-party parser; to stay dependency-free this uses
targeted regexes for the sinks that matter in web CTFs (DOM XSS, Node command
execution, eval, and prototype pollution). Matches are leads to verify.
"""
from __future__ import annotations

import re

from ..core.evidence import Finding

_RULES = [
    (re.compile(r"\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*[`'\"].*(?:\$\{|\"\s*\+|'\s*\+|\+\s*req)"),
     "OS command injection (Node)", "high",
     "A shell command is built from interpolated/concatenated input.", "CWE-78"),
    (re.compile(r"\bnew\s+Function\s*\(|\beval\s*\("),
     "Dynamic code execution (eval/Function)", "medium",
     "Check whether user input reaches eval()/new Function().", "CWE-95"),
    (re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write\s*\("),
     "DOM HTML injection sink", "medium",
     "Check whether user-controlled content reaches this DOM sink.", "CWE-79"),
    (re.compile(r"location\.(?:href|hash|search)|document\.URL|window\.name"),
     "DOM input source", "informational",
     "A client-side input source; trace it to a DOM sink for DOM XSS.", "CWE-79"),
    (re.compile(r"res\.sendFile\s*\(.*(?:req\.|\+)|fs\.readFile(?:Sync)?\s*\(.*req\."),
     "Path traversal (Node file read)", "medium",
     "A file path appears to come from the request.", "CWE-22"),
    (re.compile(r"_\.merge\s*\(|Object\.assign\s*\([^,]*,\s*(?:req|JSON\.parse)|__proto__"),
     "Prototype pollution sink", "medium",
     "Merging untrusted input into objects can pollute the prototype.", "CWE-1321"),
    (re.compile(r"jwt\.verify\s*\([^)]*algorithms?\s*:\s*\[?\s*['\"]none|jwt\.decode\s*\([^)]*verify\s*:\s*false"),
     "JWT signature not enforced", "high",
     "JWT verification allows alg=none or is disabled.", "CWE-347"),
]


# Whole-file: a recursive merge/extend that copies by key with no __proto__ guard.
_FORIN = re.compile(r"for\s*\(\s*(?:let|var|const)?\s*\w+\s+in\s+\w+\s*\)")
_BRACKET_ASSIGN = re.compile(r"\w+\[\s*\w+\s*\]\s*=\s*\w+\[\s*\w+\s*\]")
_MERGE_NAME = re.compile(r"(?i)\b(?:function\s+)?(?:merge|extend|assign|deep\w*|mixin|defaults?)\b")
_PP_GUARD = re.compile(r"__proto__|hasOwnProperty|Object\.create\(\s*null\s*\)|constructor")


def analyze_js(name: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        for pattern, title, conf, why, cwe in _RULES:
            if pattern.search(line):
                findings.append(Finding(
                    title, conf, f"{name}:{i}", line.strip()[:170], why,
                    "Verify the input source and any sanitization.",
                    origin="source", cwe=cwe))

    # Prototype-pollution gadget: key-copying recursive merge with no guard.
    if (_FORIN.search(source) and _BRACKET_ASSIGN.search(source)
            and _MERGE_NAME.search(source) and not _PP_GUARD.search(source)):
        m = _FORIN.search(source)
        line_no = source[:m.start()].count("\n") + 1
        findings.append(Finding(
            "Unsafe recursive merge (prototype pollution)", "high", f"{name}:{line_no}",
            lines[line_no - 1].strip()[:170] if line_no <= len(lines) else "for..in merge",
            "A recursive key-copying merge with no __proto__/hasOwnProperty guard "
            "lets attacker-controlled keys reach Object.prototype (prototype pollution).",
            "Trace user input into this merge; pollute a gadget (e.g. role/isAdmin) to escalate.",
            origin="source", cwe="CWE-1321"))
    return findings
