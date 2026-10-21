"""Flag recognition engine.

Recognises common CTF flag formats, supports a user-supplied custom regex, and
can peel back one or two layers of Base64 / hex / URL / ROT13 encoding to find a
flag that was encoded in a response or file. Every match is reported with the
decoding chain that produced it, so nothing is accepted on faith.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
from dataclasses import dataclass

# Known CTF flag prefixes (case-insensitive).
KNOWN_PREFIXES = (
    "flag", "ctf", "htb", "picoctf", "dpch", "ctflearn", "sekai", "actf",
    "ictf", "bhmea", "uiuctf", "corctf", "dice", "grey", "idek", "lactf",
    "wgmy", "n0ps", "pctf", "csawctf", "tjctf", "hkcert", "securinets",
)
# Matches only a known prefix (used when peeling encoding layers, where a
# generic Word{...} match is almost always decoding noise).
KNOWN_PREFIX_REGEX = r"(?i:" + "|".join(KNOWN_PREFIXES) + r")\{[^{}\r\n]{1,256}\}"

# Known prefixes OR a generic "Word{...}" shape (used on primary text).
DEFAULT_FLAG_REGEX = (
    r"(?:(?i:" + "|".join(KNOWN_PREFIXES) + r")"
    r"|[A-Za-z][A-Za-z0-9_]{1,25})"
    r"\{[^{}\r\n]{1,256}\}"
)

# Strings that merely *look* like flags but are placeholders/examples.
_PLACEHOLDER = re.compile(
    r"^(?:flag|ctf|example|test|sample|fake|dummy|redacted|xxx+|todo|changeme|your)"
    r"\{(?:[.]{3}|…|xxx+|flag|redacted|example|test|here|secret|value|placeholder|"
    r"\?+|\*+|[_\-\s]*)\}$",
    re.IGNORECASE,
)

_B64 = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
_B64URL = re.compile(r"[A-Za-z0-9_\-]{12,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")


@dataclass(frozen=True)
class FlagPatterns:
    """Two patterns: a permissive one for primary text, a strict one for decoded
    layers (known prefixes only) to avoid accepting decoding noise as flags."""

    shallow: re.Pattern[str]
    deep: re.Pattern[str]


@dataclass(frozen=True)
class FlagMatch:
    value: str
    chain: tuple[str, ...]           # e.g. ("response",) or ("response","base64","hex")

    @property
    def method(self) -> str:
        if len(self.chain) <= 1:
            return "response-body"
        return "decode:" + ">".join(self.chain[1:])

    @property
    def decoded(self) -> bool:
        return len(self.chain) > 1


def compile_pattern(custom_regex: str = "", flag_only: bool = False) -> re.Pattern[str]:
    """Build the flag pattern.

    With *flag_only* the default formats are dropped and only *custom_regex* is
    used. Otherwise a custom regex is ORed with the built-in formats.
    """
    if custom_regex and flag_only:
        return re.compile(custom_regex)
    if custom_regex:
        return re.compile(f"(?:{custom_regex})|(?:{DEFAULT_FLAG_REGEX})")
    return re.compile(DEFAULT_FLAG_REGEX)


def compile_patterns(custom_regex: str = "", flag_only: bool = False) -> FlagPatterns:
    """Build shallow + deep patterns. The deep pattern (for decoded layers) uses
    only known prefixes, plus the custom regex when supplied."""
    shallow = compile_pattern(custom_regex, flag_only)
    if custom_regex and flag_only:
        deep = re.compile(custom_regex)
    elif custom_regex:
        deep = re.compile(f"(?:{custom_regex})|(?:{KNOWN_PREFIX_REGEX})")
    else:
        deep = re.compile(KNOWN_PREFIX_REGEX)
    return FlagPatterns(shallow=shallow, deep=deep)


def looks_like_placeholder(value: str) -> bool:
    """True for obvious example/placeholder flags that should not be trusted."""
    if _PLACEHOLDER.match(value.strip()):
        return True
    inner = value[value.find("{") + 1: value.rfind("}")]
    if not inner:
        return True
    low = inner.lower()
    if low in {"flag", "example", "test", "redacted", "...", "xxx", "your_flag_here",
               "placeholder", "secret", "value"}:
        return True
    # All identical characters, e.g. flag{xxxxxxxx}
    if len(set(inner)) == 1 and len(inner) <= 12:
        return True
    return False


def find_flags(text: str, pattern: re.Pattern[str] | None = None) -> set[str]:
    """Return the set of flag-shaped strings directly present in *text*."""
    pat = pattern or compile_pattern()
    return {m.group(0) for m in pat.finditer(text)}


def find_flags_deep(text: str, patterns: "FlagPatterns | re.Pattern[str] | None" = None,
                    max_depth: int = 2) -> list[FlagMatch]:
    """Find flags directly, and after peeling encoding layers.

    *patterns* may be a :class:`FlagPatterns` (preferred) or a single compiled
    pattern (used shallow; decoded layers then fall back to known prefixes).
    Deterministic and bounded: at most *max_depth* layers, and a capped number
    of candidate tokens per layer, so it cannot blow up on large inputs.
    """
    if isinstance(patterns, FlagPatterns):
        shallow, deep = patterns.shallow, patterns.deep
    elif patterns is not None:
        shallow, deep = patterns, re.compile(KNOWN_PREFIX_REGEX)
    else:
        pats = compile_patterns()
        shallow, deep = pats.shallow, pats.deep
    results: dict[str, FlagMatch] = {}
    seen: set[str] = set()

    def record(value: str, chain: tuple[str, ...]) -> None:
        if value not in results:
            results[value] = FlagMatch(value=value, chain=chain)

    def walk(blob: str, chain: tuple[str, ...], depth: int) -> None:
        if not blob or len(blob) > 2_000_000:
            return
        digest = blob[:4096]
        if digest in seen:
            return
        seen.add(digest)
        for value in find_flags(blob, shallow if depth == 0 else deep):
            record(value, chain)
        if depth >= max_depth:
            return
        for label, decoder, finder in _DECODERS:
            count = 0
            for token in finder(blob):
                if count >= 40:
                    break
                count += 1
                decoded = decoder(token)
                if decoded and decoded != blob:
                    walk(decoded, chain + (label,), depth + 1)

    walk(text, ("response",), 0)
    return list(results.values())


# --- decoders (each returns decoded text or '') ---------------------------

def _try_b64(token: str) -> str:
    token = token.strip()
    if len(token) % 4:
        token += "=" * (4 - len(token) % 4)
    try:
        raw = base64.b64decode(token, validate=False)
    except (binascii.Error, ValueError):
        return ""
    return _printable(raw)


def _try_b64url(token: str) -> str:
    token = token.strip()
    if len(token) % 4:
        token += "=" * (4 - len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(token)
    except (binascii.Error, ValueError):
        return ""
    return _printable(raw)


def _try_hex(token: str) -> str:
    try:
        raw = bytes.fromhex(token)
    except ValueError:
        return ""
    return _printable(raw)


def _try_percent(token: str) -> str:
    try:
        return urllib.parse.unquote(token)
    except Exception:  # pragma: no cover - unquote is very forgiving
        return ""


def _try_rot13(token: str) -> str:
    try:
        return codecs.decode(token, "rot_13")
    except Exception:  # pragma: no cover
        return ""


def _printable(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:  # pragma: no cover
            return ""
    # Require it to be mostly printable to avoid noise.
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    if not text or printable / len(text) < 0.9:
        return ""
    return text


def _rot13_tokens(blob: str):
    # Only bother with whole blob + brace-y chunks; ROT13 keeps length/shape.
    if "{" in blob and "}" in blob:
        yield blob
    for chunk in re.findall(r"[A-Za-z][A-Za-z0-9_{}]{3,80}", blob):
        yield chunk


_DECODERS = (
    ("base64", _try_b64, lambda b: _B64.findall(b)),
    ("base64url", _try_b64url, lambda b: _B64URL.findall(b)),
    ("hex", _try_hex, lambda b: _HEX.findall(b)),
    ("url", _try_percent, lambda b: _PERCENT.findall(b)),
    ("rot13", _try_rot13, _rot13_tokens),
)
