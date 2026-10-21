"""Run configuration: scope, budgets, and deterministic feature switches.

Everything the engine does is governed by an explicit :class:`RunConfig`. There
are no hidden network calls, no AI/LLM inference, and no implicit escalation of
scope. Active payload sending and bounded flag retrieval are opt-in.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RunConfig:
    """All knobs for a single run. Safe, low-impact defaults."""

    # --- Scope & budgets -------------------------------------------------
    max_pages: int = 20
    """Maximum same-origin pages the crawler will fetch."""
    max_tests: int = 150
    """Hard cap on active probe requests (shared across every scanner)."""
    timeout: float = 8.0
    """Per-request timeout in seconds."""
    delay: float = 0.1
    """Delay between requests (politeness / rate limiting)."""
    max_time: float = 0.0
    """Overall wall-clock budget in seconds (0 = unlimited)."""

    # --- Behaviour -------------------------------------------------------
    active: bool = False
    """Send test payloads. Passive crawl + flag spotting only when False."""
    solve: bool = False
    """After a bug is confirmed, attempt bounded read-only flag retrieval."""
    guess_params: bool = False
    """Also test a short list of common parameter names on the base URL."""
    enum_paths: bool = True
    """Probe a short list of common CTF paths during active scanning."""

    # --- Auth / transport ------------------------------------------------
    cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    # --- Flags -----------------------------------------------------------
    flag_regex: str = ""
    """Custom flag regex. When set it is searched in addition to defaults."""
    flag_only: bool = False
    """If True, only the custom regex is used (ignore built-in flag formats)."""

    # --- Scanner selection ----------------------------------------------
    only: tuple[str, ...] = ()
    """Run only these scanner names (empty = all registered scanners)."""
    skip: tuple[str, ...] = ()
    """Skip these scanner names."""

    # --- Output ----------------------------------------------------------
    output_dir: str = ""
    quiet: bool = False
    no_color: bool = False
    verbose: bool = False

    def clamped(self) -> "RunConfig":
        """Return a copy with every budget forced into a sane range."""
        return RunConfig(
            max_pages=_clamp(self.max_pages, 1, 2000),
            max_tests=_clamp(self.max_tests, 0, 20000),
            timeout=_clampf(self.timeout, 0.5, 120.0),
            delay=_clampf(self.delay, 0.0, 60.0),
            max_time=max(0.0, float(self.max_time)),
            active=self.active,
            solve=self.solve,
            guess_params=self.guess_params,
            enum_paths=self.enum_paths,
            cookie=self.cookie,
            headers=dict(self.headers),
            flag_regex=self.flag_regex,
            flag_only=self.flag_only,
            only=tuple(self.only),
            skip=tuple(self.skip),
            output_dir=self.output_dir,
            quiet=self.quiet,
            no_color=self.no_color,
            verbose=self.verbose,
        )


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def _clampf(value: float, low: float, high: float) -> float:
    return max(low, min(high, float(value)))
