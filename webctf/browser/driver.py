"""Optional headless-browser driver (experimental).

Playwright is an *optional* dependency (``pip install web-ctf-kit[browser]``).
When it is not installed, :func:`available` returns False and the rest of the
toolkit works normally — browser automation is only needed to *confirm* that a
reflected-markup finding actually executes JavaScript, or to act as a local admin
bot when testing your own fixtures. Core detection never requires it.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


@dataclass
class VisitResult:
    url: str
    status: int = 0
    html: str = ""
    console: list[str] = field(default_factory=list)
    dialogs: list[str] = field(default_factory=list)
    screenshot: str = ""
    xss_executed: bool = False
    error: str = ""


def visit(url: str, *, timeout: float = 15.0, screenshot_path: str = "",
          xss_marker: str = "") -> VisitResult:
    """Render *url* in headless Chromium and report console/dialog activity.

    Raises RuntimeError if Playwright is not installed. ``xss_marker`` is a token
    your payload prints via ``console.log``/``alert``; its appearance confirms
    JavaScript execution (useful for verifying a reflected-XSS finding locally).
    """
    if not available():
        raise RuntimeError(
            "Playwright is not installed. Run: pip install web-ctf-kit[browser] "
            "&& python -m playwright install chromium")
    from playwright.sync_api import sync_playwright  # type: ignore

    result = VisitResult(url=url)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("console", lambda m: result.console.append(m.text))

            def _on_dialog(dialog):
                result.dialogs.append(dialog.message)
                if xss_marker and xss_marker in dialog.message:
                    result.xss_executed = True
                dialog.dismiss()

            page.on("dialog", _on_dialog)
            response = page.goto(url, timeout=int(timeout * 1000))
            page.wait_for_timeout(500)
            result.status = response.status if response else 0
            result.html = page.content()
            if xss_marker and (xss_marker in " ".join(result.console)):
                result.xss_executed = True
            if screenshot_path:
                page.screenshot(path=screenshot_path)
                result.screenshot = screenshot_path
            browser.close()
    except Exception as exc:  # pragma: no cover - requires playwright
        result.error = str(exc)
    return result
