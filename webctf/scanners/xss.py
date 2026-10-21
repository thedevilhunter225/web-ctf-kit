"""Reflected HTML / XSS scanner (markup reflection, blacklist-bypass aware).

Beyond "is my markup reflected unescaped", this prefers to report whether an
*executable* variant (an event handler or ``autofocus``) survives the server's
filter, since that — not a bare ``<h1>`` — is the exploitable condition. It walks
the probe set, and if a handler-bearing payload comes back intact it reports a
high-confidence executable-XSS finding naming the bypass that worked.
"""
from __future__ import annotations

import re

from ..core.evidence import Finding, Parameter
from ..payloads import xss as payloads
from .base import ScanContext, Scanner, register

_HANDLER = re.compile(r"on[a-z]+\s*=", re.IGNORECASE)


def _executable(payload: str) -> bool:
    """A reflection is likely executable if an event handler or autofocus survived."""
    return "autofocus" in payload.lower() or bool(_HANDLER.search(payload))


@register
class XSSScanner(Scanner):
    name = "xss"
    category = "Reflected XSS"
    description = "Unescaped HTML/markup reflection across tag/attribute blacklist bypasses."

    def scan(self, param: Parameter, ctx: ScanContext) -> None:
        marker = "WX" + ctx.token()
        baseline, _ = ctx.trial(param, "WXBASE" + marker, category=self.category)
        if baseline is None:
            return
        encoded_seen = False
        plain_hit: tuple[str, str, object] | None = None

        for label, payload in payloads.build(marker):
            if not ctx.budget.allows():
                break
            resp, attempt = ctx.trial(param, payload, category=self.category,
                                      expected="exact markup reflected")
            if resp is None:
                break
            if payload in resp.text and payload not in baseline.text:
                if _executable(payload):
                    if attempt:
                        attempt.supports = True
                        attempt.confidence = 0.8
                        attempt.note = f"executable handler reflected via {label}"
                    ctx.result.add_finding(Finding(
                        "Reflected XSS (executable handler survived)", "high",
                        param.description,
                        f"Unescaped executable reflection via '{label}': {payload}",
                        "An event-handler/autofocus payload was reflected unescaped and "
                        "survived the filter, so this is very likely executable XSS.",
                        "Confirm in a browser; for an admin-bot challenge deliver it via "
                        "the /report endpoint (see `webctf bot`).",
                        origin="dynamic", payload=payload, cwe="CWE-79"))
                    return
                if plain_hit is None:
                    plain_hit = (label, payload, attempt)
            elif marker in resp.text and any(e in resp.text for e in payloads.ENCODED_MARKERS):
                encoded_seen = True

        # No executable variant survived; report the weaker signal we did see.
        if plain_hit is not None:
            label, payload, attempt = plain_hit
            if attempt:
                attempt.supports = True
                attempt.confidence = 0.6
                attempt.note = f"non-executable reflection via {label}"
            note = ("Markup was reflected unescaped, but no event-handler variant got "
                    "through — a tag/attribute filter may be stripping handlers. "
                    "Execution needs a handler that survives the filter.")
            if encoded_seen:
                note += " Simpler tags were HTML-encoded."
            ctx.result.add_finding(Finding(
                "Reflected HTML/XSS candidate", "medium", param.description,
                f"Unescaped reflection via '{label}': {payload}", note,
                "Find a handler that survives the filter; confirm in a browser.",
                origin="dynamic", payload=payload, cwe="CWE-79"))
        elif encoded_seen:
            ctx.result.add_finding(Finding(
                "Input reflected but HTML-encoded", "informational", param.description,
                f"Marker {marker} reflected only in encoded form.",
                "The value is reflected but escaped; XSS is unlikely here as-is.",
                "Look for a context (attribute, JS, URL) where encoding differs.",
                origin="dynamic", cwe="CWE-79"))
