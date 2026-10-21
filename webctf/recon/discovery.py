"""Short, high-signal wordlists for CTF path and parameter discovery.

These are deliberately *small*. The tool does not perform broad directory
brute-forcing; it probes a curated set of paths that frequently matter in web
CTFs (source leaks, backups, VCS metadata, debug/admin endpoints, bot report
endpoints). Keeping the list short respects rate limits and competition time.
"""
from __future__ import annotations

# Paths worth a single GET during active scanning.
COMMON_PATHS = (
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/admin", "/login", "/dashboard", "/debug", "/console",
    "/flag", "/flag.txt", "/api", "/api/", "/graphql",
    "/report", "/visit", "/bot",
    "/source", "/src", "/app.py", "/server.js", "/index.php",
    "/.git/HEAD", "/.git/config", "/.env", "/.env.example",
    "/config.php", "/config.json", "/settings.py",
    "/backup.zip", "/backup.tar.gz", "/dist.zip", "/app.zip", "/site.zip",
    "/.DS_Store", "/db.sqlite3", "/database.sqlite", "/dump.sql",
    "/phpinfo.php", "/info.php", "/test.php",
)

# Files that usually indicate a disclosure if they return 200 + body.
DISCLOSURE_PATHS = (
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.example",
    "/config.php.bak", "/index.php.bak", "/app.py.bak", "/app.py~",
    "/backup.zip", "/backup.tar.gz", "/dist.zip", "/source.zip",
    "/.DS_Store", "/dump.sql", "/db.sqlite3", "/composer.json",
    "/package.json", "/Dockerfile", "/docker-compose.yml",
)

# Query parameter names worth testing when --guess is enabled.
GUESSED_PARAMETERS = (
    "q", "search", "query", "id", "page", "p", "file", "path", "name",
    "url", "redirect", "next", "cmd", "exec", "template", "tpl", "lang",
    "include", "view", "doc", "html", "input", "msg", "message", "data",
)

# Link paths that are skipped during crawling (destructive / session-ending).
AVOID_LINK_PATHS = (
    "/logout", "/signout", "/delete", "/destroy", "/remove", "/reset",
    "/purchase", "/checkout", "/pay", "/buy", "/drop",
)
