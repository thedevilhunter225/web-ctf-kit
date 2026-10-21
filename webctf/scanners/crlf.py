"""CRLF / HTTP response header injection scanner."""
from __future__ import annotations

from ..core.evidence import Finding, Parameter
from .base import ScanContext, Scanner, register


@register
class CRLFScanner(Scanner):
    name = "crlf"
    category = "CRLF / header injection"
    description = "Detects injection of CR/LF into response headers."

    def scan(self, param: Parameter, ctx: ScanContext) -> None:
        token = "wctf" + ctx.token()
        header_name = "x-webctf-crlf"
        # urlencode in the transport percent-encodes the raw CRLF for us.
        payload = f"{param.fields.get(param.name) or '1'}\r\n{header_name}: {token}"
        resp, attempt = ctx.trial(param, payload, category=self.category,
                                  expected=f"{header_name} header = {token}")
        if resp is None:
            return
        if resp.header(header_name) == token:
            if attempt:
                attempt.supports = True
                attempt.confidence = 0.9
                attempt.note = "injected header reflected into response"
            ctx.result.add_finding(Finding(
                "CRLF / HTTP header injection", "high", param.description,
                f"Injected header '{header_name}: {token}' appeared in the response.",
                "The parameter is copied into a response header without stripping CR/LF.",
                "Can enable response splitting, header-based XSS or cache poisoning.",
                origin="dynamic", payload=payload, cwe="CWE-113"))
