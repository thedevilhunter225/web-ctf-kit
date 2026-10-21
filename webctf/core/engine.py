"""The orchestrator: recon -> (source) analysis -> plan -> scan -> solve.

This wires the deterministic pipeline together. Each stage is bounded by the
shared :class:`~webctf.core.config.RunConfig` budget, and nothing escalates scope
on its own: active probing requires ``config.active`` and flag retrieval requires
``config.solve``.
"""
from __future__ import annotations

import time
from urllib.parse import urlsplit

from .. import analyzers
from ..flags.engine import compile_patterns
from ..recon.crawler import crawl
from ..recon.discovery import GUESSED_PARAMETERS
from ..recon.fingerprint import fingerprint
from ..scanners import Budget, ScanContext, select
from ..core.evidence import Parameter
from . import planner
from .config import RunConfig
from .evidence import Result
from .target import Transport, normalize


def run(url: str, config: RunConfig, source: str | None = None) -> Result:
    """Run the full pipeline and return a merged :class:`Result`."""
    config = config.clamped()
    patterns = compile_patterns(config.flag_regex, config.flag_only)
    deadline = time.monotonic() + config.max_time if config.max_time else None

    transport = Transport(url, timeout=config.timeout, cookie=config.cookie,
                          headers=config.headers, delay=config.delay)
    mode = "solve" if (config.active and config.solve) else ("scan" if config.active else "recon")
    result = Result(target=transport.target, mode=mode)

    source_frameworks: list[str] = []
    if source:
        src = analyzers.analyze(source, flag_regex=config.flag_regex, flag_only=config.flag_only)
        for finding in src.findings:
            result.add_finding(finding)
        for flag in src.flags:
            result.add_flag(flag)
        result.visited.extend("source:" + v for v in src.visited)
        result.metadata["source"] = src.metadata
        source_frameworks = list(src.metadata.get("frameworks", []))

    # --- recon ---------------------------------------------------------
    landing = None
    try:
        landing = transport.request(transport.target)
    except (ConnectionError, ValueError) as exc:
        result.errors.append(f"GET {transport.target}: {exc}")
    fp = fingerprint(landing) if landing else fingerprint()
    result.metadata["fingerprint"] = fp.as_dict()

    crawl(transport, result, config, patterns, transport.target)

    if config.guess_params:
        base = transport.target
        existing = {(p.method, p.url, p.name) for p in result.parameters}
        for name in GUESSED_PARAMETERS:
            key = ("GET", base, name)
            if key not in existing:
                result.parameters.append(Parameter(
                    "GET", base, {}, name,
                    f"GET {urlsplit(base).path or '/'} ?{name}= [guessed]", "query"))

    # --- plan + scan ---------------------------------------------------
    budget = Budget(max_tests=config.max_tests if config.active else 0)
    ctx = ScanContext(transport, result, config, budget, patterns)
    scanners = select(config)
    all_frameworks = sorted(set(fp.frameworks) | set(source_frameworks))
    # Make stack info available to scanners/exploits during the run (not just in
    # the final report), e.g. so the PP exploit knows it's a JS target.
    result.metadata["frameworks"] = all_frameworks
    result.metadata["stack"] = fp.summary()
    site_scanners, jobs = planner.build_plan(result, all_frameworks, scanners, config)

    if config.active:
        for scanner in site_scanners:
            if _expired(deadline) or not budget.allows():
                break
            scanner.scan_site(ctx)
        for job in jobs:
            if _expired(deadline) or not budget.allows():
                break
            if job.scanner.applies(job.param, ctx):
                job.scanner.scan(job.param, ctx)

        # --- solve (bounded, read-only flag retrieval) -----------------
        if config.solve and not _expired(deadline):
            from ..exploits import run_pp_exploit, run_solve
            if ctx.solve_targets:
                run_solve(ctx)
            best = result.best_flag()
            if not (best and best.verified) and not _expired(deadline):
                run_pp_exploit(ctx)

    result.requests = transport.count
    result.metadata.update({
        "frameworks": all_frameworks,
        "stack": fp.summary(),
        "probes_sent": budget.performed,
        "max_pages": config.max_pages,
        "max_tests": config.max_tests,
        "active": config.active,
        "solve": config.solve,
        "same_origin_only": True,
        "scanners": [s.name for s in scanners],
    })
    return result


def _expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() > deadline


# --- backwards-compatible convenience API ---------------------------------
def scan(url: str, *, active: bool = False, max_pages: int = 15,
         max_tests: int = 100, timeout: float = 6, cookie: str = "",
         headers: dict | None = None, guess: bool = False, delay: float = 0.1,
         paths: bool = True, solve: bool = False, flag_regex: str = "") -> Result:
    """Compatibility wrapper mirroring the original ``engine.scan`` signature."""
    config = RunConfig(
        active=active, max_pages=max_pages, max_tests=max_tests, timeout=timeout,
        cookie=cookie, headers=dict(headers or {}), guess_params=guess, delay=delay,
        enum_paths=paths, solve=solve, flag_regex=flag_regex,
    )
    return run(url, config)
