"""Bounded, same-origin crawler and input-parameter discovery."""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from ..core.config import RunConfig
from ..core.evidence import Finding, Parameter, Result
from ..core.target import Transport, in_scope, normalize
from ..flags.engine import FlagPatterns
from ..flags.watch import record_flags
from .discovery import AVOID_LINK_PATHS, COMMON_PATHS
from .parser import parse_page

_INTERESTING = ("/admin", "/source", "/debug", "/flag", "/.git/head", "/.env",
                "/console", "/report", "/visit", "/dump.sql", "/backup")
_JS_ENDPOINT = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{1,60}\?[A-Za-z0-9_\-=&%]{1,80})["'`]""")
_MAX_SCRIPTS = 10


def _add_param(result: Result, param: Parameter, known: set[tuple[str, str, str]]) -> None:
    key = (param.method, param.url, param.name)
    if key not in known:
        known.add(key)
        result.parameters.append(param)


def crawl(transport: Transport, result: Result, config: RunConfig,
          patterns: FlagPatterns, base_url: str) -> None:
    """Walk the in-scope site, filling ``result`` with pages, forms and params."""
    start = normalize(base_url)
    queue: deque[str] = deque([start])
    if config.active and config.enum_paths:
        queue.extend(urljoin(base_url, p) for p in COMMON_PATHS)
    seen: set[str] = set()
    known: set[tuple[str, str, str]] = set()
    scripts: set[str] = set()

    while queue and len(result.visited) < config.max_pages:
        here = queue.popleft()
        if not in_scope(base_url, here) or here in seen:
            continue
        if any(x in urlsplit(here).path.lower() for x in AVOID_LINK_PATHS):
            continue
        seen.add(here)
        try:
            response = transport.request(here)
        except (ValueError, ConnectionError) as exc:
            if len(result.errors) < 50:
                result.errors.append(f"GET {here}: {exc}")
            continue
        result.visited.append(here)
        record_flags(result, response.text, here, patterns=patterns)

        path_l = urlsplit(here).path.rstrip("/").lower()
        if here != start and response.status == 200 and any(path_l.endswith(x) for x in _INTERESTING):
            result.add_finding(Finding(
                "Interesting accessible endpoint", "low", here,
                f"GET returned HTTP {response.status}",
                "A discovered endpoint responded; inspect it for challenge hints.",
                "Open the URL and verify intended challenge behaviour."))

        current_url = normalize(here)
        if response.url != here and in_scope(base_url, response.url):
            current_url = normalize(response.url)

        for name in dict(parse_qsl(urlsplit(here).query, keep_blank_values=True)):
            fields = dict(parse_qsl(urlsplit(here).query, keep_blank_values=True))
            _add_param(result, Parameter("GET", here, fields, name,
                       f"GET {urlsplit(here).path or '/'} ?{name}=", "query"), known)

        ctype = response.header("content-type").lower()
        if "html" not in ctype and "<html" not in response.text[:500].lower():
            continue
        page = parse_page(current_url, response.text)
        scripts.update(s for s in page.scripts if in_scope(base_url, s))
        for comment in page.comments:
            record_flags(result, comment, f"{here} <!--comment-->", patterns=patterns)
        for link in sorted(page.links):
            if len(queue) + len(result.visited) >= config.max_pages * 5:
                break
            norm = normalize(link)
            if in_scope(base_url, norm) and norm not in seen:
                queue.append(norm)
        for form in page.forms:
            if not in_scope(base_url, form.action):
                continue
            result.forms.append(form)
            for name in form.editable:
                _add_param(result, Parameter(form.method, form.action, dict(form.fields),
                           name, f"{form.method} {urlsplit(form.action).path or '/'} field={name}",
                           "form"), known)

    _fetch_scripts(transport, result, config, patterns, base_url, scripts, known)


def _fetch_scripts(transport: Transport, result: Result, config: RunConfig,
                   patterns: FlagPatterns, base_url: str,
                   scripts: set[str], known: set[tuple[str, str, str]]) -> None:
    for url in sorted(scripts)[:_MAX_SCRIPTS]:
        try:
            resp = transport.request(url)
        except (ValueError, ConnectionError):
            continue
        result.visited.append(url)
        record_flags(result, resp.text, url, patterns=patterns)
        for hit in _JS_ENDPOINT.findall(resp.text)[:20]:
            abs_url = normalize(urljoin(base_url, hit))
            if not in_scope(base_url, abs_url):
                continue
            parts = urlsplit(abs_url)
            fields = dict(parse_qsl(parts.query, keep_blank_values=True))
            for name in fields:
                _add_param(result, Parameter("GET", abs_url, fields, name,
                           f"GET {parts.path or '/'} ?{name}= [from JS]", "query"), known)
