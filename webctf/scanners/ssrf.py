"""SSRF scanner (experimental, scope-safe).

Full SSRF confirmation usually needs an out-of-band listener, which this tool
does not run by default (no external callbacks). As a scope-safe heuristic, for
URL-like parameters it asks the server to fetch the challenge's *own* origin and
checks whether that content is reflected back — evidence the server performs a
server-side fetch of attacker-supplied URLs. Treated as a lead, not proof.
"""
from __future__ import annotations

from ..core.evidence import Finding, Hypothesis, Parameter
from .base import ScanContext, Scanner, register

_URL_NAMES = {"url", "uri", "link", "callback", "webhook", "target", "dest",
              "fetch", "load", "proxy", "feed", "src", "image", "img", "host"}


@register
class SSRFScanner(Scanner):
    name = "ssrf"
    category = "Server-side request forgery"
    experimental = True
    description = "(experimental) Flags URL-like params and scope-safe fetch reflection."

    def applies(self, param: Parameter, ctx: ScanContext) -> bool:
        return param.name.lower() in _URL_NAMES

    def scan(self, param: Parameter, ctx: ScanContext) -> None:
        # A distinctive marker page on the same origin is unavailable, so we use
        # the target root and look for its reflection.
        if not getattr(ctx, "_ssrf_sig", None):
            try:
                root = ctx.transport.request(ctx.transport.target)
                ctx._ssrf_sig = root.text[:200]
            except (ConnectionError, ValueError):
                ctx._ssrf_sig = ""
        sig = (ctx._ssrf_sig or "").strip()
        resp, attempt = ctx.trial(param, ctx.transport.target, category=self.category,
                                  expected="server fetches and reflects own origin")
        if resp is None:
            return
        reflected = len(sig) > 30 and sig[:60] in resp.text
        ctx.result.add_hypothesis(Hypothesis(
            "SSRF", param.description,
            "URL-like parameter; verify server-side fetch behaviour manually.",
            priority=40, source="param-name", scanner="ssrf"))
        if reflected:
            if attempt:
                attempt.supports = True
                attempt.confidence = 0.5
            ctx.result.add_finding(Finding(
                "Server-side request forgery (experimental)", "medium", param.description,
                "Server fetched and reflected its own origin for a supplied URL.",
                "The parameter triggers a server-side HTTP fetch; internal targets may be reachable.",
                "Manually test internal addresses permitted by the challenge scope.",
                origin="dynamic", payload=ctx.transport.target, cwe="CWE-918"))
