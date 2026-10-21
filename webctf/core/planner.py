"""Deterministic exploit planner.

The planner is pure, rule-based prioritisation — no randomness, no AI. It fuses
three signals into an ordered list of ``(scanner, parameter)`` jobs:

1. **Fingerprint** — the detected stack boosts the relevant bug classes
   (Flask/Jinja2 -> SSTI, PHP -> LFI/SQLi, Express -> SSRF/prototype pollution).
2. **Source findings** — when challenge source is provided, confirmed-looking
   sinks sharply raise the matching scanner's priority and point it at inputs.
3. **Parameter names** — ``file``/``path`` -> LFI, ``url``/``next`` -> redirect,
   ``cmd``/``host`` -> command injection, ``id`` -> SQLi, ``tpl`` -> SSTI, etc.

Running the highest-value probes first means flags are found sooner and the test
budget is spent where the evidence points.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .config import RunConfig
from .evidence import Hypothesis, Parameter, Result

# framework substring -> {scanner: boost}
_FRAMEWORK_BOOST = {
    "flask": {"ssti": 40, "xss": 10},
    "jinja": {"ssti": 45},
    "werkzeug": {"ssti": 35},
    "django": {"sqli": 15, "ssti": 10},
    "tornado": {"ssti": 30},
    "php": {"lfi": 35, "sqli": 25, "disclosure": 15},
    "laravel": {"sqli": 20, "lfi": 15},
    "express": {"ssrf": 20, "sqli": 15, "crlf": 10},
    "node": {"ssrf": 20, "cmdi": 10},
    "rails": {"sqli": 20},
}

# (keywords, scanner, boost) — matched against the parameter name.
_PARAM_HINTS: list[tuple[set[str], str, int]] = [
    ({"file", "filename", "path", "page", "doc", "template_path", "include",
      "view", "download", "load", "read", "img", "image"}, "lfi", 45),
    ({"url", "uri", "next", "redirect", "redir", "return", "dest", "callback",
      "continue", "goto", "link", "to"}, "redirect", 40),
    ({"url", "uri", "callback", "webhook", "fetch", "proxy", "feed", "host",
      "target"}, "ssrf", 25),
    ({"cmd", "command", "exec", "run", "ping", "host", "ip", "domain", "dns",
      "lookup"}, "cmdi", 45),
    ({"id", "uid", "pid", "user_id", "num", "page", "order", "sort", "cat",
      "category", "product"}, "sqli", 35),
    ({"username", "user", "name", "login", "email", "pass", "password"}, "sqli", 25),
    ({"template", "tpl", "tmpl", "preview", "render", "msg", "message",
      "name", "greeting"}, "ssti", 35),
    ({"q", "search", "query", "s", "keyword", "name", "comment", "msg",
      "message", "html", "input", "text", "body"}, "xss", 30),
    ({"data", "payload", "obj", "json", "input"}, "crlf", 10),
]

# source-finding category substring -> {scanner: boost}
_SOURCE_BOOST = [
    ("template", {"ssti": 60}),
    ("ssti", {"ssti": 70}),
    ("autoescape", {"xss": 40, "ssti": 20}),
    ("xss", {"xss": 45}),
    ("dom html", {"xss": 25}),
    ("sql", {"sqli": 60}),
    ("command", {"cmdi": 60}),
    ("deserial", {"ssti": 5}),
    ("file path", {"lfi": 55}),
    ("path traversal", {"lfi": 60}),
    ("traversal", {"lfi": 50}),
    ("redirect", {"redirect": 40}),
    ("request forgery", {"ssrf": 45}),
    ("ssrf", {"ssrf": 45}),
    ("crlf", {"crlf": 45}),
    ("header injection", {"crlf": 40}),
    ("filter", {"xss": 20}),
]


@dataclass
class Job:
    score: int
    scanner: object          # Scanner instance
    param: Parameter

    def __lt__(self, other: "Job") -> bool:  # for stable sorting
        return self.score < other.score


def _framework_base(fingerprint_frameworks: list[str]) -> dict[str, int]:
    base: dict[str, int] = {}
    blob = " ".join(fingerprint_frameworks).lower()
    for needle, boosts in _FRAMEWORK_BOOST.items():
        if needle in blob:
            for scanner, boost in boosts.items():
                base[scanner] = base.get(scanner, 0) + boost
    return base


def _source_base(result: Result) -> dict[str, int]:
    base: dict[str, int] = {}
    for finding in result.findings:
        if finding.origin != "source":
            continue
        cat = finding.category.lower()
        weight = 1.0 if finding.confidence in ("high", "confirmed") else 0.5
        for needle, boosts in _SOURCE_BOOST:
            if needle in cat:
                for scanner, boost in boosts.items():
                    base[scanner] = base.get(scanner, 0) + int(boost * weight)
    return base


def _param_bonus(scanner_name: str, param: Parameter) -> int:
    key = param.name.lower()
    bonus = 0
    for keywords, scanner, boost in _PARAM_HINTS:
        if scanner != scanner_name:
            continue
        if key in keywords or any(key.endswith("_" + k) or key.endswith(k) for k in keywords):
            bonus = max(bonus, boost)
    return bonus


def build_plan(result: Result, fingerprint_frameworks: list[str], scanners: list,
               config: RunConfig) -> tuple[list, list[Job]]:
    """Return ``(site_scanners, jobs)`` ordered by descending priority."""
    fw_base = _framework_base(fingerprint_frameworks)
    src_base = _source_base(result)
    base: dict[str, int] = {}
    for table in (fw_base, src_base):
        for k, v in table.items():
            base[k] = base.get(k, 0) + v

    site_scanners = [s for s in scanners if s.scope == "site"]
    param_scanners = [s for s in scanners if s.scope == "param"]

    # Record a few top hypotheses for transparency in the report.
    for scanner_name, score in sorted(base.items(), key=lambda kv: -kv[1])[:6]:
        if score <= 0:
            continue
        result.add_hypothesis(Hypothesis(
            category=scanner_name.upper(), target="(stack/source)",
            rationale="Prioritised by fingerprint/source signals.",
            priority=min(100, 50 + score), source="planner", scanner=scanner_name))

    jobs: list[Job] = []
    for param in result.parameters:
        for scanner in param_scanners:
            # cheap applicability filter is applied later by the engine, but we
            # skip obviously-irrelevant scoped scanners here to save slots.
            score = 50 + base.get(scanner.name, 0) + _param_bonus(scanner.name, param)
            if scanner.experimental:
                score -= 15
            jobs.append(Job(score=score, scanner=scanner, param=param))
    # Highest score first; stable by insertion order for equal scores.
    jobs.sort(key=lambda j: j.score, reverse=True)
    site_scanners.sort(key=lambda s: base.get(s.name, 0), reverse=True)
    return site_scanners, jobs


# convenience for param-name only hypotheses (used by recon-only runs)
_FILE_RE = re.compile(r"file|path|page|include|template", re.I)
