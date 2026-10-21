"""Markdown report generation."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from ..core.evidence import Result
from ..core.evidence import CONFIDENCE_ORDER


def _rank(conf: str) -> int:
    try:
        return CONFIDENCE_ORDER.index(conf)
    except ValueError:
        return len(CONFIDENCE_ORDER)


def as_markdown(report: Result) -> str:
    md = report.metadata or {}
    lines = [
        "# Web CTF Kit report", "",
        f"- Target: `{report.target}`",
        f"- Mode: `{report.mode}`",
        f"- Stack: `{md.get('stack', 'unknown')}`",
        f"- Created: `{datetime.now(timezone.utc).isoformat(timespec='seconds')}`",
        f"- HTTP requests: `{report.requests}`",
        f"- Active probes: `{md.get('probes_sent', 0)}`",
        f"- Pages/files inspected: `{len(report.visited)}`",
        f"- Parameters discovered: `{len(report.parameters)}`",
        f"- Findings: `{len(report.findings)}`", "",
        "> Probe findings are leads unless marked **confirmed**; a confirmed "
        "finding is backed by a reproducible exploitation artifact.", "",
    ]

    if report.flags:
        lines += ["## Flags", ""]
        for flag in sorted(report.flags, key=lambda f: (not f.verified,)):
            tag = "VERIFIED" if flag.verified else "unverified"
            lines.append(f"- **`{flag.value}`** ({tag}) — via {flag.method} at `{flag.location}`")
        lines.append("")

    lines += ["## Findings", ""]
    if not report.findings:
        lines += ["No findings matched built-in checks.", ""]
    for idx, f in enumerate(report.sorted_findings(), 1):
        lines += [
            f"### {idx}. {f.category} ({f.confidence})", "",
            f"- Location: `{f.location}`",
            f"- Source: `{f.origin}`" + (f" · CWE: `{f.cwe}`" if f.cwe else ""),
            f"- Evidence: `{f.evidence.replace(chr(96), chr(39))}`",
        ]
        if f.payload:
            lines.append(f"- Payload: `{f.payload.replace(chr(96), chr(39))}`")
        lines += [
            f"- Why: {f.explanation}",
            f"- Next step: {f.recommendation or 'Manually verify.'}", "",
        ]

    if report.hypotheses:
        lines += ["## Hypotheses (planner)", ""]
        for h in sorted(report.hypotheses, key=lambda x: -x.priority):
            lines.append(f"- [p{h.priority}] `{h.category}` @ `{h.target}` — {h.rationale} ({h.source})")
        lines.append("")

    lines += ["## Discovered input parameters", ""]
    lines += [f"- `{p.description}`" for p in report.parameters] or ["- None."]

    if md.get("source"):
        s = md["source"]
        lines += ["", "## Source analysis", "",
                  f"- Files examined: `{s.get('files_examined', 0)}`",
                  f"- Frameworks: `{', '.join(s.get('frameworks', [])) or 'unknown'}`"]
        routes = s.get("routes", [])
        if routes:
            lines.append("- Routes:")
            lines += [f"  - `{r}`" for r in routes[:40]]

    lines += ["", "## Visited locations", ""]
    lines += [f"- `{x}`" for x in report.visited[:120]] or ["- None."]

    lines += ["", "## Probe attempts", "",
              f"Total active probe attempts recorded: `{len(report.attempts)}`."]
    supported = [a for a in report.attempts if a.supports]
    if supported:
        lines += ["", "Attempts that supported a finding:"]
        for a in supported[:40]:
            lines.append(f"- `{a.category}` @ `{a.target}` — payload `{a.payload[:80]}` → {a.note}")

    lines += ["", "## Errors", ""]
    lines += [f"- {x}" for x in report.errors[:30]] or ["- None."]

    lines += ["", "## Summary", ""]
    for conf, n in sorted(Counter(f.confidence for f in report.findings).items(),
                          key=lambda kv: _rank(kv[0])):
        lines.append(f"- {conf}: {n}")
    return "\n".join(lines) + "\n"
