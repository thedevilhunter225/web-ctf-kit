"""Structured evidence: findings, probe attempts, hypotheses, flags and results.

Nothing here is ever presented as "confirmed" without a reproducible artifact.
Confidence is explicit on every finding, and every active probe is recorded as
an :class:`Attempt` so a run can be audited and reproduced by hand.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# Ordered from strongest to weakest for sorting/printing.
CONFIDENCE_ORDER = ("confirmed", "observed", "high", "medium", "low", "informational")


def _conf_rank(value: str) -> int:
    try:
        return CONFIDENCE_ORDER.index(value)
    except ValueError:
        return len(CONFIDENCE_ORDER)


@dataclass
class Finding:
    """A single result. ``confidence`` is one of :data:`CONFIDENCE_ORDER`.

    ``confirmed`` is reserved for results backed by a reproducible exploitation
    artifact (e.g. a flag read out through the bug, or deterministic template
    arithmetic). Everything weaker is a *lead*, not proof.
    """

    category: str
    confidence: str
    location: str
    evidence: str
    explanation: str
    recommendation: str = ""
    origin: str = "dynamic"          # dynamic | source | recon | exploit
    payload: str = ""
    cwe: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Attempt:
    """One active probe and its outcome, for reproducibility and planning."""

    category: str
    target: str
    payload: str
    expected: str
    actual: str
    status: int = 0
    confidence: float = 0.0          # 0..1 heuristic support for the hypothesis
    supports: bool = False
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Hypothesis:
    """A suspected vulnerability the planner wants to test, with a priority."""

    category: str
    target: str
    rationale: str
    priority: int = 50               # higher = test earlier
    source: str = "heuristic"        # source | fingerprint | param-name | heuristic
    scanner: str = ""                # which scanner should handle it

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Flag:
    """A recovered flag-shaped string and exactly how it was obtained."""

    value: str
    location: str
    method: str                      # response-body | decode:* | lfi | ssti | sqli | cmdi | source
    verified: bool = False           # True only when obtained via exploitation/decoding

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Form:
    action: str
    method: str
    fields: dict[str, str] = field(default_factory=dict)
    editable: list[str] = field(default_factory=list)


@dataclass
class Parameter:
    method: str
    url: str
    fields: dict[str, str]
    name: str
    description: str
    kind: str = "query"              # query | form | json | header | cookie


@dataclass
class Result:
    """Everything a run produced. Serialises to JSON via :meth:`as_dict`."""

    target: str
    mode: str
    visited: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    attempts: list[Attempt] = field(default_factory=list)
    flags: list[Flag] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    requests: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    # -- mutation helpers (all de-duplicating) ---------------------------
    def add_finding(self, f: Finding) -> None:
        key = (f.category, f.location, f.evidence)
        if not any((x.category, x.location, x.evidence) == key for x in self.findings):
            self.findings.append(f)

    def add_hypothesis(self, h: Hypothesis) -> None:
        key = (h.category, h.target)
        if not any((x.category, x.target) == key for x in self.hypotheses):
            self.hypotheses.append(h)

    def add_attempt(self, a: Attempt) -> None:
        self.attempts.append(a)

    def add_flag(self, flag: Flag) -> None:
        for existing in self.flags:
            if existing.value == flag.value:
                # Prefer the verified / most specific record.
                if flag.verified and not existing.verified:
                    existing.verified = True
                    existing.method = flag.method
                    existing.location = flag.location
                return
        self.flags.append(flag)

    # -- queries ---------------------------------------------------------
    def best_flag(self) -> Flag | None:
        if not self.flags:
            return None
        return sorted(self.flags, key=lambda f: (not f.verified,))[0]

    def confirmed(self) -> list[Finding]:
        return [f for f in self.findings if f.confidence == "confirmed"]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (_conf_rank(f.confidence), f.category, f.location))

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mode": self.mode,
            "visited": self.visited,
            "forms": [asdict(x) for x in self.forms],
            "parameters": [asdict(x) for x in self.parameters],
            "findings": [x.as_dict() for x in self.sorted_findings()],
            "hypotheses": [x.as_dict() for x in self.hypotheses],
            "attempts": [x.as_dict() for x in self.attempts],
            "flags": [x.as_dict() for x in self.flags],
            "errors": self.errors,
            "requests": self.requests,
            "metadata": self.metadata,
        }
