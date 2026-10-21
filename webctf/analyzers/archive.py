"""Bounded, in-memory iteration over source trees and archives.

Supports directories, ZIP, TAR and TAR.GZ/TGZ, and single files. Archives are
read entirely in memory and never extracted to disk, so a malicious archive
cannot plant files (e.g. a ``../`` traversal entry) or be executed. Hard limits
on file count, per-file size and total bytes keep analysis fast and safe.
"""
from __future__ import annotations

import tarfile
import zipfile
from collections.abc import Iterator
from pathlib import Path

MAX_FILES = 800
MAX_TOTAL_BYTES = 48 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024

EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".vue", ".html", ".htm",
    ".php", ".phtml", ".jsp", ".java", ".rb", ".erb", ".go", ".rs", ".jinja",
    ".jinja2", ".j2", ".ejs", ".hbs", ".twig", ".sql", ".yaml", ".yml", ".env",
    ".txt", ".md", ".json", ".toml", ".ini", ".cfg", ".conf", ".sh", ".dockerfile",
}
# Files matched by exact (lower) basename even without a listed suffix.
SPECIAL_NAMES = {"dockerfile", "docker-compose.yml", "docker-compose.yaml",
                 "makefile", "procfile", ".env", ".flaskenv", "requirements.txt"}
SKIP_DIRS = {".git", ".venv", "node_modules", "venv", "__pycache__", "build",
             "dist-info", ".mypy_cache", ".pytest_cache", "site-packages"}


def _wanted(name: str) -> bool:
    p = Path(name)
    if p.suffix.lower() in EXTENSIONS:
        return True
    return p.name.lower() in SPECIAL_NAMES


def _skip(parts) -> bool:
    return any(part in SKIP_DIRS for part in parts)


def iter_sources(path: Path) -> Iterator[tuple[str, str]]:
    """Yield ``(relative_name, text)`` for each in-scope source file."""
    if path.is_dir():
        yield from _iter_dir(path)
    elif zipfile.is_zipfile(path):
        yield from _iter_zip(path)
    elif tarfile.is_tarfile(path):
        yield from _iter_tar(path)
    elif path.is_file():
        if path.stat().st_size <= MAX_FILE:
            yield path.name, path.read_text(encoding="utf-8", errors="replace")
    else:
        raise FileNotFoundError(f"No such source path: {path}")


def _iter_dir(root: Path) -> Iterator[tuple[str, str]]:
    count = total = 0
    for file in sorted(root.rglob("*")):
        if count >= MAX_FILES:
            break
        rel = file.relative_to(root)
        if _skip(rel.parts) or file.is_symlink() or not file.is_file():
            continue
        if not _wanted(file.name):
            continue
        size = file.stat().st_size
        if size > MAX_FILE or total + size > MAX_TOTAL_BYTES:
            continue
        try:
            content = file.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            continue
        count += 1
        total += size
        yield str(rel).replace("\\", "/"), content


def _iter_zip(path: Path) -> Iterator[tuple[str, str]]:
    count = total = 0
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            if count >= MAX_FILES:
                break
            if member.is_dir() or member.file_size > MAX_FILE:
                continue
            if total + member.file_size > MAX_TOTAL_BYTES or _skip(Path(member.filename).parts):
                continue
            if not _wanted(member.filename):
                continue
            try:
                with archive.open(member) as stream:
                    data = stream.read(MAX_FILE + 1)
                content = data.decode("utf-8")
            except (UnicodeError, OSError, RuntimeError):
                continue
            count += 1
            total += member.file_size
            yield member.filename, content


def _iter_tar(path: Path) -> Iterator[tuple[str, str]]:
    count = total = 0
    with tarfile.open(path) as archive:
        for member in archive:
            if count >= MAX_FILES:
                break
            if not member.isfile() or member.size > MAX_FILE:
                continue
            if total + member.size > MAX_TOTAL_BYTES or _skip(Path(member.name).parts):
                continue
            if not _wanted(member.name):
                continue
            try:
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                content = extracted.read(MAX_FILE + 1).decode("utf-8")
            except (UnicodeError, OSError, tarfile.TarError):
                continue
            count += 1
            total += member.size
            yield member.name, content
