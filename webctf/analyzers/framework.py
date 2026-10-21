"""Framework / language identification from source files and config."""
from __future__ import annotations

import re

# framework -> (regex over file contents, language)
_SIGNS = [
    ("Flask", re.compile(r"from\s+flask\s+import|Flask\s*\(\s*__name__|flask\.Flask"), "python"),
    ("Django", re.compile(r"django\.|urlpatterns\s*=|DJANGO_SETTINGS_MODULE|manage\.py"), "python"),
    ("FastAPI", re.compile(r"from\s+fastapi\s+import|FastAPI\s*\("), "python"),
    ("Tornado", re.compile(r"tornado\.web|tornado\.ioloop"), "python"),
    ("Bottle", re.compile(r"from\s+bottle\s+import|bottle\.route"), "python"),
    ("Express/Node.js", re.compile(r"require\(['\"]express['\"]\)|from\s+['\"]express['\"]"), "javascript"),
    ("Koa", re.compile(r"require\(['\"]koa['\"]\)"), "javascript"),
    ("Next.js", re.compile(r"next/|getServerSideProps|__NEXT_DATA__"), "javascript"),
    ("Laravel", re.compile(r"Illuminate\\\\|artisan|laravel/framework"), "php"),
    ("Symfony", re.compile(r"Symfony\\\\Component|symfony/"), "php"),
    ("CodeIgniter", re.compile(r"CodeIgniter|system/core"), "php"),
    ("Rails", re.compile(r"Rails\.application|ActionController|config/routes\.rb"), "ruby"),
    ("Spring", re.compile(r"org\.springframework|@SpringBootApplication|@RestController"), "java"),
    ("Gin (Go)", re.compile(r"gin-gonic/gin|gin\.Default\("), "go"),
]

_JS_ROUTE = re.compile(r"""\b(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['"`]([^'"`]+)['"`]""")
_PHP_ROUTE = re.compile(r"""Route::(get|post|put|delete|patch|any)\s*\(\s*['"]([^'"]+)['"]""")


def identify(files: dict[str, str]) -> dict:
    """Return ``{frameworks, languages, routes, entrypoints, config_files}``."""
    frameworks: set[str] = set()
    languages: set[str] = set()
    routes: list[str] = []
    entrypoints: list[str] = []
    config_files: list[str] = []

    for name, content in files.items():
        low = name.lower()
        base = low.rsplit("/", 1)[-1]
        if base in ("app.py", "main.py", "wsgi.py", "server.js", "index.js",
                    "index.php", "app.js", "manage.py", "run.py"):
            entrypoints.append(name)
        if base in ("config.py", "settings.py", "config.php", "config.json",
                    ".env", ".flaskenv", "requirements.txt", "composer.json",
                    "package.json", "dockerfile", "docker-compose.yml"):
            config_files.append(name)
        for fw, pattern, lang in _SIGNS:
            if pattern.search(content):
                frameworks.add(fw)
                languages.add(lang)
        for verb, path in _JS_ROUTE.findall(content):
            routes.append(f"{verb.upper()} {path}")
        for verb, path in _PHP_ROUTE.findall(content):
            routes.append(f"{verb.upper()} {path}")

    return {
        "frameworks": sorted(frameworks),
        "languages": sorted(languages),
        "routes": sorted(set(routes)),
        "entrypoints": sorted(set(entrypoints)),
        "config_files": sorted(set(config_files)),
    }
