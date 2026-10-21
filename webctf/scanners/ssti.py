"""Server-side template injection scanner (arithmetic evaluation evidence)."""
from __future__ import annotations

from ..core.evidence import Finding, Hypothesis, Parameter
from ..payloads import ssti as payloads
from .base import ScanContext, Scanner, register

# Random-ish operands; product (8897) is not a well-known SSTI signature.
_A, _B = 287, 31


@register
class SSTIScanner(Scanner):
    name = "ssti"
    category = "Server-side template injection"
    description = "Detects template-expression evaluation via arithmetic across engines."

    def scan(self, param: Parameter, ctx: ScanContext) -> None:
        # Bracket delimiters so the probe itself can never match a flag pattern
        # (a word-prefixed "{...}" would otherwise look like a flag).
        wrapper = "[z" + ctx.token() + "]"
        baseline, _ = ctx.trial(param, wrapper + "plain", category=self.category)
        if baseline is None:
            return
        for label, payload, expected in payloads.arithmetic(wrapper, _A, _B):
            if not ctx.budget.allows():
                return
            resp, attempt = ctx.trial(param, payload, category=self.category, expected=expected)
            if resp is None:
                return
            # Confirmed only if the product rendered and the literal expr did not.
            if expected in resp.text and payload not in resp.text:
                if attempt:
                    attempt.supports = True
                    attempt.confidence = 0.9
                    attempt.note = f"arithmetic evaluated ({label})"
                ctx.result.add_finding(Finding(
                    "Server-side template injection", "high", param.description,
                    f"{payload} evaluated to {expected} (engine family: {label})",
                    "The server evaluated a template expression supplied as input.",
                    "Use --solve to attempt a bounded, read-only flag read via the engine.",
                    origin="dynamic", payload=payload, cwe="CWE-1336"))
                ctx.result.add_hypothesis(Hypothesis(
                    "SSTI RCE", param.description,
                    "Template arithmetic evaluated; engine likely allows object access.",
                    priority=90, source="dynamic", scanner="ssti"))
                ctx.queue_solve("ssti", param, engine=label)
                return
