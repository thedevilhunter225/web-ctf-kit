"""Glue between flag detection and the evidence model.

``record_flags`` scans a blob of text (a response body, a decoded payload, a
source file) and files both :class:`~webctf.core.evidence.Flag` records and a
de-duplicated :class:`~webctf.core.evidence.Finding` for each distinct flag.
"""
from __future__ import annotations

from ..core.evidence import Finding, Flag, Result
from .engine import FlagPatterns, compile_patterns, find_flags_deep, looks_like_placeholder


def record_flags(result: Result, text: str, location: str, *,
                 patterns: FlagPatterns | None = None,
                 origin: str = "dynamic",
                 verified: bool = False) -> list[str]:
    """Find flags in *text* and record them. Returns the list of values found.

    *verified* should be True only when the caller obtained this text through a
    confirmed exploitation primitive (e.g. an LFI read of the flag file).
    """
    pats = patterns or compile_patterns()
    found: list[str] = []
    for match in find_flags_deep(text, pats):
        value = match.value
        placeholder = looks_like_placeholder(value)
        is_verified = bool(verified or match.decoded) and not placeholder
        method = match.method if not verified else origin
        result.add_flag(Flag(value=value, location=location, method=method,
                             verified=is_verified))
        found.append(value)
        if placeholder:
            result.add_finding(Finding(
                "Flag-shaped placeholder", "informational", location, value,
                "Matches a flag format but looks like an example/placeholder value.",
                "Confirm against the real challenge flag format before submitting.",
                origin=origin))
        elif match.decoded:
            result.add_finding(Finding(
                "CTF flag (decoded)", "observed", location, value,
                f"A flag was recovered by decoding ({match.method}).",
                "Strong lead; verify it is the challenge flag.",
                origin=origin))
        else:
            result.add_finding(Finding(
                "Possible CTF flag", "observed", location, value,
                "A recognizable flag-format string was observed.",
                "Submit only after checking the challenge flag format.",
                origin=origin))
    return found
