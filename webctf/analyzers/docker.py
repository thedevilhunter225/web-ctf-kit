"""Dockerfile and docker-compose analysis (flag/secret/port hints)."""
from __future__ import annotations

import re

from ..core.evidence import Finding

try:  # optional; falls back to regex when unavailable
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:  # pragma: no cover
    _HAVE_YAML = False

_ENV_LINE = re.compile(r"(?im)^\s*ENV\s+([A-Z0-9_]+)[\s=]+(.+)$")
_ARG_LINE = re.compile(r"(?im)^\s*ARG\s+([A-Z0-9_]+)")
_EXPOSE = re.compile(r"(?im)^\s*EXPOSE\s+([\d\s]+)")
_FLAGISH = re.compile(r"(?i)flag|secret|token|password|passwd|key")


def analyze_dockerfile(name: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for m in _ENV_LINE.finditer(content):
        key, value = m.group(1), m.group(2).strip()
        line_no = content[:m.start()].count("\n") + 1
        if _FLAGISH.search(key):
            findings.append(Finding(
                "Secret/flag in Docker ENV", "high", f"{name}:{line_no}",
                f"ENV {key}=[value withheld]",
                "A flag or secret is baked into the image environment; an in-container "
                "RCE/SSTI/LFI that can read env vars or the process environment would expose it.",
                "Target os.environ / process env once you have code or template execution.",
                origin="source", cwe="CWE-200"))
    ports = _EXPOSE.findall(content)
    if ports:
        findings.append(Finding(
            "Exposed container ports", "informational", name,
            "EXPOSE " + " ".join(p.strip() for p in ports),
            "Ports the challenge container exposes.",
            "Note the service port(s) for the live target.", origin="source"))
    return findings


def analyze_compose(name: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    env_items: list[tuple[str, str]] = []
    if _HAVE_YAML:
        try:
            data = yaml.safe_load(content) or {}
            for svc in (data.get("services") or {}).values():
                env = svc.get("environment") if isinstance(svc, dict) else None
                if isinstance(env, dict):
                    env_items.extend((k, str(v)) for k, v in env.items())
                elif isinstance(env, list):
                    for item in env:
                        if isinstance(item, str) and "=" in item:
                            k, v = item.split("=", 1)
                            env_items.append((k, v))
        except Exception:
            env_items = []
    if not env_items:  # regex fallback
        for m in re.finditer(r"(?im)^\s*-?\s*([A-Z0-9_]+)\s*[:=]\s*(.+)$", content):
            env_items.append((m.group(1), m.group(2).strip()))
    for key, _value in env_items:
        if _FLAGISH.search(key):
            findings.append(Finding(
                "Secret/flag in compose environment", "high", name,
                f"{key}=[value withheld]",
                "A flag/secret is provided to a service via environment; reachable "
                "through env-reading execution primitives.",
                "Target the process environment after achieving code/template execution.",
                origin="source", cwe="CWE-200"))
    return findings
