"""OS command injection scanner (read-only echo-marker detection)."""
from __future__ import annotations

from ..core.evidence import Finding, Hypothesis, Parameter
from ..payloads import cmdi as payloads
from .base import ScanContext, Scanner, register

_CMD_NAMES = {"cmd", "command", "exec", "run", "ping", "host", "ip", "addr",
              "domain", "dns", "lookup", "target", "query", "name", "url"}


def _cmd_ish(name: str) -> bool:
    key = name.lower()
    return any(key == x or key.endswith("_" + x) or key.endswith(x) for x in _CMD_NAMES)


@register
class CommandInjectionScanner(Scanner):
    name = "cmdi"
    category = "OS command injection"
    description = "Detects shell command injection by echoing a unique marker."

    def scan(self, param: Parameter, ctx: ScanContext) -> None:
        value = param.fields.get(param.name) or "127.0.0.1"
        marker = "WC" + ctx.token()
        base, _ = ctx.trial(param, value, category=self.category)
        if base is None:
            return
        probes = payloads.echo_probes(marker)
        if not _cmd_ish(param.name):
            probes = probes[:3]
        for payload in probes:
            if not ctx.budget.allows():
                return
            injected = value + payload
            resp, attempt = ctx.trial(param, injected, category=self.category,
                                      expected=f"marker {marker} echoed")
            if resp is None:
                return
            # The marker must appear because `echo` executed, not merely because
            # the app reflected our input verbatim. If the whole injected string
            # is echoed back, that is reflection (handled by the XSS scanner).
            if marker in resp.text and marker not in base.text and injected not in resp.text:
                if attempt:
                    attempt.supports = True
                    attempt.confidence = 0.9
                    attempt.note = "echo marker returned"
                ctx.result.add_finding(Finding(
                    "OS command injection", "high", param.description,
                    f"Injected 'echo {marker}' output appeared in the response.",
                    "The parameter is concatenated into a shell command.",
                    "Use --solve to attempt a bounded, read-only flag read (cat).",
                    origin="dynamic", payload=value + payload, cwe="CWE-78"))
                ctx.result.add_hypothesis(Hypothesis(
                    "Command execution flag read", param.description,
                    "Shell metacharacters execute; read-only cat can retrieve a flag.",
                    priority=88, source="dynamic", scanner="cmdi"))
                ctx.queue_solve("cmdi", param, value=value)
                return
