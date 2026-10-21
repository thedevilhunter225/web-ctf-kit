"""Prototype-pollution detection (site-scoped).

Detection surface for the active PP -> privesc auto-exploit. On an active scan it
raises a hypothesis when there is evidence a JS app pollutes Object.prototype (a
JS stack, or a source-flagged merge / JSON-interpolation sink). The actual
escalation + flag read runs in the solve phase (see
:func:`webctf.exploits.proto_pollute.run_pp_exploit`), so it only fires under
``--solve``.
"""
from __future__ import annotations

from ..core.evidence import Hypothesis
from .base import ScanContext, Scanner, register


@register
class ProtoPollutionScanner(Scanner):
    name = "pp"
    category = "Prototype pollution"
    scope = "site"
    experimental = True
    description = ("Prototype-pollution privilege escalation for JS apps "
                   "(auto-exploited under --solve: register/login, pollute, read flag).")

    def scan_site(self, ctx: ScanContext) -> None:
        r = ctx.result
        frameworks = " ".join(r.metadata.get("frameworks", [])).lower()
        js_stack = any(k in frameworks for k in ("node", "express", "koa", "next", "javascript"))
        pp_evidence = any(
            k in f.category.lower()
            for f in r.findings
            for k in ("prototype pollution", "json built from string"))
        if js_stack or pp_evidence:
            why = ("source flags a merge/JSON-interpolation sink"
                   if pp_evidence else "JS stack detected")
            r.add_hypothesis(Hypothesis(
                "Prototype pollution privesc", "(site)",
                f"Candidate PP target ({why}); use --solve to auto-escalate.",
                priority=65, source="dynamic", scanner="pp"))
