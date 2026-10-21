"""JSON report writing and loading."""
from __future__ import annotations

import json
from pathlib import Path

from ..core.evidence import Result
from .markdown import as_markdown


def save_report(report: Result, output: str) -> tuple[Path, Path]:
    """Write ``findings.json`` and ``report.md`` into *output*; return their paths."""
    destination = Path(output)
    destination.mkdir(parents=True, exist_ok=True)
    j = destination / "findings.json"
    m = destination / "report.md"
    j.write_text(json.dumps(report.as_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    m.write_text(as_markdown(report), encoding="utf-8")
    return j, m


def load_result(path: str) -> dict:
    """Load a previously saved ``findings.json`` as a dict (for ``webctf report``)."""
    return json.loads(Path(path).read_text(encoding="utf-8"))
