"""Open redirect scanner (out-of-scope Location header, never followed)."""
from __future__ import annotations

from ..core.evidence import Finding, Parameter
from .base import ScanContext, Scanner, register

_REDIRECT_NAMES = {"url", "next", "redirect", "redir", "return", "return_to",
                   "returnurl", "continue", "dest", "destination", "callback",
                   "goto", "to", "out", "link", "target"}


@register
class OpenRedirectScanner(Scanner):
    name = "redirect"
    category = "Open redirect"
    description = "Detects user-controlled redirects to an external destination."

    def applies(self, param: Parameter, ctx: ScanContext) -> bool:
        return param.name.lower() in _REDIRECT_NAMES

    def scan(self, param: Parameter, ctx: ScanContext) -> None:
        marker = f"https://example.invalid/webctf-{ctx.token()}"
        resp, attempt = ctx.trial(param, marker, category=self.category,
                                  expected="external Location header")
        if resp is None:
            return
        dest = resp.header("location")
        if resp.status in (301, 302, 303, 307, 308) and dest.startswith(marker):
            if attempt:
                attempt.supports = True
                attempt.confidence = 0.85
                attempt.note = "redirect to external marker"
            ctx.result.add_finding(Finding(
                "Open redirect", "high", param.description,
                "Location: " + dest,
                "A user-controlled value sets the redirect destination to an external URL.",
                "Check whether the redirect can be chained with the challenge objective.",
                origin="dynamic", payload=marker, cwe="CWE-601"))
