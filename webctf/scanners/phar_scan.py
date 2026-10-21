"""PHAR-deserialization detection (site-scoped).

Detection surface for the active phar-deserialization auto-exploit. When source
analysis found a PHP POP gadget plus an upload / phar file-op sink, it raises a
hypothesis; the actual craft-upload-trigger-read-flag runs in the solve phase
(see :func:`webctf.exploits.phar_deser.run_phar_exploit`).
"""
from __future__ import annotations

from ..core.evidence import Hypothesis
from .base import ScanContext, Scanner, register


@register
class PharDeserScanner(Scanner):
    name = "phar"
    category = "PHP phar deserialization"
    scope = "site"
    experimental = True
    description = ("PHP phar:// object-injection RCE (auto-exploited under --solve: "
                   "craft GIF/PHAR gadget, upload, trigger, read flag).")

    def scan_site(self, ctx: ScanContext) -> None:
        php = ctx.result.metadata.get("php") or {}
        if php.get("gadgets") and (php.get("has_file_op") or php.get("upload_fields")):
            ctx.result.add_hypothesis(Hypothesis(
                "PHAR deserialization RCE", "(site)",
                f"POP gadget(s) {[g['class'] for g in php['gadgets']][:3]} + upload/phar "
                "sink in source; use --solve to auto-exploit.",
                priority=80, source="dynamic", scanner="phar"))
