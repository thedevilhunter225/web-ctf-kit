"""PHP source analysis: injection/upload/phar rules and POP-gadget extraction.

Covers the bug class behind "phar deserialization" challenges: insecure file
upload + a file operation on a user-influenced path (which triggers the ``phar://``
wrapper) + a serializable class whose magic method performs a dynamic call (a POP
gadget). Line rules provide the leads; :func:`find_pop_gadgets` and
:func:`php_targets` extract the structured facts the exploit module needs.
"""
from __future__ import annotations

import re

from ..core.evidence import Finding

# (regex, title, confidence, why, cwe)
_RULES = [
    (r"\bunserialize\s*\(", "PHP object injection (unserialize)", "high",
     "unserialize() on attacker-controlled data enables PHP object injection / POP chains.", "CWE-502"),
    (r"\bmove_uploaded_file\s*\(", "Insecure file upload", "medium",
     "Validate type/extension/content; web-reachable uploads are dangerous (and phar-abusable).", "CWE-434"),
    (r"(?i)preg_match\s*\(\s*['\"][^'\"]*phar", "Weak phar:// filter (bypassable)", "medium",
     "A phar:// blacklist is easy to bypass (case, compression wrappers); the regex here is "
     "typically case-sensitive, so PHAR:// slips through.", "CWE-184"),
    (r"\b(?:file_exists|file_get_contents|fopen|getimagesize|imagecreatefrom\w+|md5_file|"
     r"sha1_file|filesize|is_file|is_dir|stat|readfile|file|exif_read_data|copy|unlink|hash_file)"
     r"\s*\([^)]*\$", "File op on a dynamic path (phar:// / LFI trigger)", "high",
     "File functions on an attacker-influenced path trigger phar:// deserialization or LFI.", "CWE-502"),
    (r"\b(?:include|include_once|require|require_once)\s+[^;]*\$", "Dynamic include (LFI/RFI)", "high",
     "Including an attacker-influenced path enables LFI/RFI.", "CWE-98"),
    (r"(?<![\w>$])(?:eval|assert|create_function)\s*\([^)]*\$", "PHP code execution sink", "high",
     "User input reaching eval/assert/create_function is RCE.", "CWE-95"),
    (r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$", "OS command execution sink", "high",
     "User input in a shell command is command injection.", "CWE-78"),
    (r"\bcall_user_func(?:_array)?\s*\([^)]*\$", "Dynamic function call", "medium",
     "A variable callback can become arbitrary call if attacker-controlled.", "CWE-94"),
    (r"\$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)\b", "User-controlled input source", "informational",
     "Trace this input to a sink.", "CWE-20"),
]
_COMPILED = [(re.compile(rx), t, c, w, cwe) for rx, t, c, w, cwe in _RULES]

_MAGIC = ("__destruct", "__wakeup", "__unserialize", "__toString", "__invoke",
          "__call", "__callStatic", "__get", "__set")
# A magic method calling a property as a function: ($this->a)($this->b, $this->c)
_DYNCALL = re.compile(r"\(\s*\$this->(\w+)\s*\)\s*\((?P<args>[^;{}]*)\)")
_CUF = re.compile(r"call_user_func(?:_array)?\s*\(\s*\$this->(\w+)\s*,?(?P<args>[^;{}]*)\)")
_THIS_PROP = re.compile(r"\$this->(\w+)")
_CLASS = re.compile(r"\bclass\s+(\w+)")
_FILES = re.compile(r"\$_FILES\s*\[\s*['\"](\w+)['\"]")
_POST = re.compile(r"\$_(?:POST|GET|REQUEST)\s*\[\s*['\"](\w+)['\"]")


def analyze_php(name: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    for i, line in enumerate(lines, 1):
        if not line.strip() or len(line) > 2000:
            continue
        for pattern, title, conf, why, cwe in _COMPILED:
            if pattern.search(line):
                findings.append(Finding(title, conf, f"{name}:{i}", line.strip()[:170], why,
                                        "Trace the input and confirm reachability.",
                                        origin="source", cwe=cwe))
    for g in find_pop_gadgets(source):
        ln = g["line"]
        findings.append(Finding(
            "PHP POP gadget (magic method dynamic call)", "high", f"{name}:{ln}",
            (lines[ln - 1].strip()[:170] if 0 < ln <= len(lines) else g["class"]),
            f"Class {g['class']}::{g['method']} calls a property as a function "
            f"(${{this}}->{g['runner']}(...)) — a ready POP gadget for RCE if this object "
            "is unserialized (e.g. via phar://).",
            "Combine with an unserialize/phar sink to reach code execution.",
            origin="source", cwe="CWE-502"))
    return findings


def _method_bodies(source: str):
    """Yield (method_name, start_line, body_text, start_pos) for magic methods."""
    for m in re.finditer(r"function\s+(__\w+)\s*\([^)]*\)\s*\{", source):
        name = m.group(1)
        if name not in _MAGIC:
            continue
        i = m.end() - 1  # at the opening '{'
        depth, j = 0, m.end() - 1
        while j < len(source):
            ch = source[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield name, source[:m.start()].count("\n") + 1, source[i:j + 1], m.start()


def _class_at(source: str, pos: int) -> str:
    name = "UnknownClass"
    for m in _CLASS.finditer(source):
        if m.start() < pos:
            name = m.group(1)
        else:
            break
    return name


def find_pop_gadgets(source: str) -> list[dict]:
    """Return dynamic-call POP gadgets: {class, method, runner, args, line}.

    ``runner`` is the property used as the callable; ``args`` are the property
    names passed to it (in order). The exploit sets ``runner`` to a command
    function and the first arg to the command.
    """
    gadgets: list[dict] = []
    for method, line, body, pos in _method_bodies(source):
        for rx in (_DYNCALL, _CUF):
            m = rx.search(body)
            if not m:
                continue
            runner = m.group(1)
            args = _THIS_PROP.findall(m.group("args") or "")
            gadgets.append({"class": _class_at(source, pos), "method": method,
                            "runner": runner, "args": args, "line": line})
            break
    return gadgets


def php_targets(files: dict[str, str]) -> dict:
    """Aggregate PHP exploitation facts across all source files."""
    gadgets: list[dict] = []
    upload_fields: list[str] = []
    post_fields: list[str] = []
    has_file_op = False
    has_phar_filter = False
    for name, body in files.items():
        if not name.lower().endswith((".php", ".phtml", ".php5", ".inc")):
            continue
        gadgets.extend(find_pop_gadgets(body))
        upload_fields.extend(_FILES.findall(body))
        post_fields.extend(_POST.findall(body))
        if re.search(r"\b(?:file_exists|include|require|file_get_contents|fopen|getimagesize|md5_file)\b", body):
            has_file_op = True
        if re.search(r"(?i)preg_match\s*\(\s*['\"][^'\"]*phar", body):
            has_phar_filter = True
    # de-dup, preserve order
    def uniq(seq):
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
    return {
        "gadgets": gadgets,
        "upload_fields": uniq(upload_fields),
        "post_fields": uniq(post_fields),
        "has_file_op": has_file_op,
        "has_phar_filter": has_phar_filter,
        "exploitable": bool(gadgets and (has_file_op or upload_fields)),
    }
