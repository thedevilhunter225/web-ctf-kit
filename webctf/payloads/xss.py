"""Reflected-markup probes, including common tag/attribute blacklist bypasses.

Each probe contains a unique ``{m}`` marker. A probe is considered reflected
only when the *exact* markup comes back unescaped and was not present in the
baseline response. Actual JavaScript execution still requires a real browser
(see :mod:`webctf.browser`); these probes prove unescaped HTML injection.
"""
from __future__ import annotations

# (label, template). Ordered from benign to bypass-oriented so the report shows
# the simplest working injection first.
PROBES: list[tuple[str, str]] = [
    ("plain-tag", "<h1>{m}</h1>"),
    ("event-handler", '<h1 autofocus tabindex="0" onfocus="void(0)">{m}</h1>'),
    ("img-onerror", '<img src=x onerror="void(0)" alt="{m}">'),
    ("svg-onload", '<svg onload="void(0)">{m}</svg>'),
    ("uppercase-tag", "<SCRIPT>void(0)</SCRIPT><b>{m}</b>"),
    ("broken-tag", "<x/onclick=void(0)>{m}"),
    ("attribute-breakout", '"><b>{m}</b>'),
    ("details-ontoggle", '<details open ontoggle="void(0)">{m}</details>'),
]

# Fragments that indicate HTML-encoding of the marker (i.e. NOT injectable).
ENCODED_MARKERS = ("&lt;", "&gt;", "&#x3c;", "&#60;", "&quot;")


def build(marker: str) -> list[tuple[str, str]]:
    """Return ``[(label, payload), ...]`` with *marker* substituted in."""
    return [(label, tpl.replace("{m}", marker)) for label, tpl in PROBES]
