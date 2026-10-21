"""Source / backup / VCS / config disclosure scanner (site-scoped)."""
from __future__ import annotations

import json
import re

from ..core.evidence import Finding
from ..recon.discovery import DISCLOSURE_PATHS
from .base import ScanContext, Scanner, register

_GIT_HEAD = re.compile(r"ref:\s*refs/")
_ENV_LINE = re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\S")
_ZIP_MAGIC = ("PK\x03\x04", "PK\x05\x06")
_SQLITE_MAGIC = "SQLite format 3"
_HTML = re.compile(r"(?i)<!doctype html|<html|<body|<form|<head")
_DOCKER_FROM = re.compile(r"(?im)^\s*FROM\s+\S")
_COMPOSE = re.compile(r"(?im)^\s*(services|version)\s*:")
_CODEISH = re.compile(r"<\?php|def\s|function\s|SELECT\s|INSERT\s|import\s|require\(|=\s*['\"]")
_JSON_KEYS = {"name", "version", "dependencies", "require", "scripts",
              "devDependencies", "main", "license"}


@register
class DisclosureScanner(Scanner):
    name = "disclosure"
    category = "Source/backup disclosure"
    scope = "site"
    description = "Checks for exposed .git, .env, backups, DB dumps and source files."

    def scan_site(self, ctx: ScanContext) -> None:
        for path in DISCLOSURE_PATHS:
            if not ctx.budget.allows():
                return
            resp = ctx.fetch(path, category=self.category)
            if resp is None or resp.status != 200 or not resp.text.strip():
                continue
            body = resp.text
            low = path.lower()
            kind, conf, why = self._classify(low, body)
            if kind is None:
                continue
            ctx.result.add_finding(Finding(
                kind, conf, path, (body[:160] + "…") if len(body) > 160 else body,
                why, "Download and inspect; it may contain source, secrets or a flag.",
                origin="recon", cwe="CWE-200"))

    @staticmethod
    def _classify(path: str, body: str):
        # File-type-specific signals first (these are unambiguous even if an app
        # also serves HTML for unknown paths).
        if path.endswith("/.git/head") and _GIT_HEAD.search(body):
            return "Exposed .git repository", "high", "A .git HEAD reference is served; the repo may be dumpable."
        if path.endswith("/.git/config") and "[core]" in body:
            return "Exposed .git repository", "high", "The .git/config file is publicly readable."
        if path.endswith(".env") and _ENV_LINE.search(body) and not _HTML.search(body[:500]):
            return "Exposed .env file", "high", "Environment file with KEY=VALUE pairs is readable."
        if any(m in body[:8] for m in _ZIP_MAGIC):
            return "Exposed backup/source archive", "high", "A ZIP archive is downloadable at a guessable path."
        if body.startswith(_SQLITE_MAGIC):
            return "Exposed SQLite database", "high", "A SQLite database file is downloadable."

        # Everything below is ambiguous, so reject responses that are just the
        # application's HTML page (common when an app returns 200 for any path).
        if _HTML.search(body[:1000]):
            return None, "", ""
        if path.endswith(("composer.json", "package.json")):
            try:
                obj = json.loads(body)
            except (ValueError, TypeError):
                return None, "", ""
            if isinstance(obj, dict) and (_JSON_KEYS & set(obj)):
                return "Exposed build/config metadata", "low", "Dependency/build metadata is readable."
            return None, "", ""
        if path.endswith("dockerfile") and _DOCKER_FROM.search(body):
            return "Exposed build/config metadata", "low", "A Dockerfile is readable."
        if path.endswith(("docker-compose.yml", "docker-compose.yaml")) and _COMPOSE.search(body):
            return "Exposed build/config metadata", "low", "A compose file is readable."
        if (path.endswith((".bak", ".bak~", "~", ".sql")) or path.endswith(".php.bak")) and _CODEISH.search(body):
            return "Exposed source/backup file", "medium", "A backup or source file is readable."
        return None, "", ""
