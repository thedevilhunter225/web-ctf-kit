"""Terminal output. Uses ANSI colour when attached to a TTY; plain otherwise.

Rich is used for the banner when available, but the tool never *requires* it, so
output stays clean and deterministic when piped or captured (e.g. in tests).
"""
from __future__ import annotations

import sys

from ..core.evidence import Result

_CODES = {"reset": "\033[0m", "bold": "\033[1m", "green": "\033[32m",
          "yellow": "\033[33m", "red": "\033[31m", "cyan": "\033[36m",
          "grey": "\033[90m", "magenta": "\033[35m"}

_CONF_COLOR = {"confirmed": "green", "observed": "cyan", "high": "red",
               "medium": "yellow", "low": "grey", "informational": "grey"}


def _use_color(no_color: bool) -> bool:
    return not no_color and sys.stdout.isatty()


def _paint(text: str, color: str, on: bool) -> str:
    if not on or color not in _CODES:
        return text
    return f"{_CODES[color]}{text}{_CODES['reset']}"


def print_banner(no_color: bool = False) -> None:
    on = _use_color(no_color)
    title = "WEB CTF SOLVER  --  deterministic, no-AI toolkit for authorized CTFs"
    bar = "=" * len(title)
    print(_paint(bar, "cyan", on))
    print(_paint(title, "bold", on))
    print(_paint(bar, "cyan", on))


def _line(tag: str, text: str, color: str, on: bool) -> None:
    print(f"{_paint('[' + tag + ']', color, on)} {text}")


def print_summary(report: Result, *, no_color: bool = False, verbose: bool = False) -> None:
    on = _use_color(no_color)
    md = report.metadata or {}
    _line("+", f"Target: {report.target}", "green", on)
    _line("+", f"Mode: {report.mode}  |  Stack: {md.get('stack', 'unknown')}", "green", on)
    if md.get("source"):
        s = md["source"]
        _line("+", f"Source analyzed: {s.get('files_examined', 0)} files, "
                   f"frameworks: {', '.join(s.get('frameworks', [])) or 'unknown'}", "green", on)
    _line("+", f"Discovered: {len(report.visited)} locations, "
               f"{len(report.parameters)} input parameters", "green", on)
    if md.get("active"):
        _line("+", f"Active probes sent: {md.get('probes_sent', 0)} "
                   f"({report.requests} total requests)", "green", on)

    findings = report.sorted_findings()
    confirmed = [f for f in findings if f.confidence == "confirmed"]
    strong = [f for f in findings if f.confidence in ("high", "observed")]
    _line("+", f"Findings: {len(findings)} "
               f"({len(confirmed)} confirmed, {len(strong)} high/observed)", "green", on)

    shown = findings if verbose else findings[:20]
    for f in shown:
        color = _CONF_COLOR.get(f.confidence, "grey")
        tag = "+" if f.confidence in ("confirmed", "high", "observed") else "*"
        loc = f"\n      {_paint(f.location, 'grey', on)}"
        ev = f.evidence if len(f.evidence) <= 160 else f.evidence[:160] + "..."
        _line(tag, _paint(f"{f.category} ({f.confidence})", color, on) + loc +
              f"\n      {ev}", color, on)
    if not verbose and len(findings) > 20:
        print(f"  ... {len(findings) - 20} more findings (see the saved report)")

    if report.errors:
        _line("!", f"{len(report.errors)} error(s); first: {report.errors[0]}", "yellow", on)

    print()
    best = report.best_flag()
    if best and best.verified:
        _line("+", _paint(f"FLAG: {best.value}", "green", on) +
              _paint(f"   (verified via {best.method})", "grey", on), "green", on)
    elif report.flags:
        print(_paint("Flag-shaped strings found (unverified - check the format):", "yellow", on))
        for flag in report.flags:
            print(f"   {flag.value}   ({flag.method} @ {flag.location})")
    else:
        _line("-", "No flag recovered. See findings/report for leads.", "grey", on)


def print_result_dict(data: dict, *, no_color: bool = False) -> None:
    """Pretty-print a previously saved findings.json (for ``webctf report``)."""
    on = _use_color(no_color)
    print_banner(no_color)
    _line("+", f"Target: {data.get('target')}  |  Mode: {data.get('mode')}", "green", on)
    flags = data.get("flags", [])
    findings = data.get("findings", [])
    _line("+", f"Findings: {len(findings)}  |  Flags: {len(flags)}  |  "
               f"Requests: {data.get('requests', 0)}", "green", on)
    for f in findings[:40]:
        color = _CONF_COLOR.get(f.get("confidence", ""), "grey")
        tag = "+" if f.get("confidence") in ("confirmed", "high", "observed") else "*"
        _line(tag, _paint(f"{f.get('category')} ({f.get('confidence')})", color, on) +
              f"\n      {f.get('location')}\n      {f.get('evidence', '')[:160]}", color, on)
    print()
    verified = [f for f in flags if f.get("verified")]
    if verified:
        _line("+", _paint(f"FLAG: {verified[0]['value']}", "green", on), "green", on)
    elif flags:
        print("Unverified flag-shaped strings:")
        for f in flags:
            print(f"   {f['value']}")
