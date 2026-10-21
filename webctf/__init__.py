"""Web CTF Kit: deterministic, no-AI reconnaissance, analysis and exploitation
for authorized Capture-The-Flag web challenges.

Public API::

    from webctf import solve, analyze_source, RunConfig
    result = solve("http://127.0.0.1:8000/", RunConfig(active=True, solve=True))
    print(result.best_flag())

Only test local labs and CTF instances you are authorized to access.
"""
from __future__ import annotations

__version__ = "0.2.0"


def solve(url: str, config=None, source: str | None = None):
    """Run the full pipeline against *url*. See :class:`webctf.core.config.RunConfig`."""
    from .core.config import RunConfig
    from .core.engine import run
    return run(url, config or RunConfig(active=True, solve=True), source=source)


def analyze_source(path: str, flag_regex: str = "", flag_only: bool = False):
    """Offline source analysis of a ZIP/TAR/dir/file."""
    from .analyzers import analyze
    return analyze(path, flag_regex=flag_regex, flag_only=flag_only)


__all__ = ["__version__", "solve", "analyze_source"]
