"""HTML link / form / script discovery using Python's built-in HTMLParser."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin

from ..core.evidence import Form


class PageParser(HTMLParser):
    def __init__(self, url: str):
        super().__init__(convert_charrefs=True)
        self.url = url
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.comments: list[str] = []
        self.forms: list[Form] = []
        self.current: Form | None = None
        self.current_textarea: str | None = None
        self.current_option: tuple[str, str] | None = None
        self.select_name: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("a", "link") and a.get("href"):
            self.links.add(urljoin(self.url, a["href"]))
        if tag == "script" and a.get("src"):
            self.scripts.add(urljoin(self.url, a["src"]))
        if tag == "form":
            action = urljoin(self.url, a.get("action") or self.url)
            method = (a.get("method") or "GET").upper()
            self.current = Form(action=action, method=method)
        elif tag == "input" and self.current is not None and a.get("name"):
            kind = a.get("type", "text").lower()
            if kind in ("button", "submit", "image", "reset", "file"):
                return
            name = a["name"]
            if kind in ("radio", "checkbox") and "checked" not in a:
                return
            self.current.fields[name] = a.get("value", "")
            if kind not in ("hidden", "radio", "checkbox") and name not in self.current.editable:
                self.current.editable.append(name)
        elif tag == "textarea" and self.current is not None and a.get("name"):
            self.current_textarea = a["name"]
            self.current.fields[self.current_textarea] = ""
            if self.current_textarea not in self.current.editable:
                self.current.editable.append(self.current_textarea)
        elif tag == "select" and self.current is not None and a.get("name"):
            self.select_name = a["name"]
            self.current.fields[self.select_name] = ""
            self.current.editable.append(self.select_name)
        elif tag == "option" and self.current is not None and self.select_name:
            self.current_option = (self.select_name, a.get("value", ""))

    def handle_data(self, data: str):
        if self.current_textarea and self.current:
            self.current.fields[self.current_textarea] += data
        if self.current_option and self.current:
            field, value = self.current_option
            if not value and not self.current.fields[field]:
                self.current.fields[field] = data.strip()

    def handle_comment(self, data: str):
        snippet = data.strip()
        if snippet and len(self.comments) < 50:
            self.comments.append(snippet[:300])

    def handle_endtag(self, tag: str):
        if tag == "textarea":
            self.current_textarea = None
        if tag == "option":
            if self.current_option and self.current:
                field, value = self.current_option
                if not self.current.fields[field]:
                    self.current.fields[field] = value
            self.current_option = None
        if tag == "select":
            self.select_name = None
        if tag == "form" and self.current:
            if self.current.method in ("GET", "POST"):
                self.forms.append(self.current)
            self.current = None


def parse_page(url: str, html: str) -> PageParser:
    parser = PageParser(url)
    parser.feed(html)
    parser.close()
    return parser
