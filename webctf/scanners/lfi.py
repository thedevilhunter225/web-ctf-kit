"""Local file inclusion / path traversal scanner (/etc/passwd confirmation)."""
from __future__ import annotations

import re

from ..core.evidence import Finding, Hypothesis, Parameter
from ..payloads import lfi as payloads
from .base import ScanContext, Scanner, register

_ROOT_LINE = re.compile(r"(?m)^root:[^\n]{0,120}:0:0:")
_FILE_NAMES = {"file", "filename", "filepath", "path", "page", "doc", "document",
               "template", "include", "view", "download", "source", "load", "read",
               "cat", "name", "img", "image", "lang", "locale"}


def _file_ish(name: str) -> bool:
    key = name.lower()
    return any(key == x or key.endswith("_" + x) or key.endswith(x) for x in _FILE_NAMES)


@register
class LFIScanner(Scanner):
    name = "lfi"
    category = "Path traversal / local file read"
    description = "Confirms directory traversal by reading /etc/passwd's root entry."

    def scan(self, param: Parameter, ctx: ScanContext) -> None:
        probes = payloads.PASSWD_PROBES if _file_ish(param.name) else payloads.PASSWD_PROBES[:2]
        for payload in probes:
            if not ctx.budget.allows():
                return
            resp, attempt = ctx.trial(param, payload, category=self.category,
                                      expected="root:x:0:0 entry")
            if resp is None:
                return
            if _ROOT_LINE.search(resp.text):
                if attempt:
                    attempt.supports = True
                    attempt.confidence = 0.95
                    attempt.note = "/etc/passwd root line returned"
                ctx.result.add_finding(Finding(
                    "Path traversal / local file read", "high", param.description,
                    f"/etc/passwd root entry returned for payload: {payload}",
                    "The parameter reads arbitrary local files outside the intended directory.",
                    "Use --solve to attempt a bounded read of conventional flag paths.",
                    origin="dynamic", payload=payload, cwe="CWE-22"))
                ctx.result.add_hypothesis(Hypothesis(
                    "LFI flag read", param.description,
                    "Arbitrary file read confirmed via /etc/passwd.",
                    priority=85, source="dynamic", scanner="lfi"))
                ctx.queue_solve("lfi", param, confirmed=True)
                return
