"""Lightweight Python taint analysis using the standard-library AST.

This is a conservative, flow-insensitive source-to-sink correlation: it collects
every variable assigned (directly or via string building) from a request source,
then flags dangerous sinks that receive one of those tainted values. It is not a
full dataflow engine, but it finds the classic "user input reaches eval / SQL /
template / command / file" bugs that dominate web CTFs, with far fewer false
positives than a line regex, and it also extracts Flask/FastAPI routes.
"""
from __future__ import annotations

import ast

from ..core.evidence import Finding

# Attributes of `request`/`req` that are user-controlled sources.
_SOURCE_ATTRS = {"args", "form", "values", "json", "data", "files", "cookies",
                 "headers", "get_json", "query", "body", "params", "GET", "POST",
                 "REQUEST", "input", "stream"}
_SOURCE_ROOTS = {"request", "req", "flask_request"}

# callee-name -> (category, confidence, explanation, cwe, which-args)
# which-args: "first" | "any" | "sql" (formatted-string heuristic) | "subprocess"
_SINKS = {
    "render_template_string": ("SSTI (user input to template string)", "high",
        "User input reaches render_template_string -> server-side template injection.",
        "CWE-1336", "first"),
    "eval": ("Code injection (eval)", "high",
        "User input reaches eval().", "CWE-95", "first"),
    "exec": ("Code injection (exec)", "high",
        "User input reaches exec().", "CWE-95", "first"),
    "system": ("OS command injection", "high",
        "User input reaches os.system().", "CWE-78", "first"),
    "popen": ("OS command injection", "high",
        "User input reaches os.popen().", "CWE-78", "first"),
    "getoutput": ("OS command injection", "high",
        "User input reaches commands.getoutput().", "CWE-78", "first"),
    "run": ("OS command injection", "medium",
        "User input reaches subprocess.run (check shell=True).", "CWE-78", "subprocess"),
    "Popen": ("OS command injection", "medium",
        "User input reaches subprocess.Popen (check shell=True).", "CWE-78", "subprocess"),
    "call": ("OS command injection", "medium",
        "User input reaches subprocess.call (check shell=True).", "CWE-78", "subprocess"),
    "check_output": ("OS command injection", "medium",
        "User input reaches subprocess.check_output (check shell=True).", "CWE-78", "subprocess"),
    "execute": ("SQL injection", "high",
        "User input reaches a DB execute() via string building.", "CWE-89", "sql"),
    "executescript": ("SQL injection", "high",
        "User input reaches executescript() via string building.", "CWE-89", "sql"),
    "open": ("Path traversal / file read", "medium",
        "User input reaches open(); validate the path.", "CWE-22", "first"),
    "send_file": ("Path traversal / file read", "high",
        "User input reaches send_file(); validate the path.", "CWE-22", "first"),
    "loads": ("Unsafe deserialization", "high",
        "User input reaches a loads() deserializer.", "CWE-502", "first"),
    "unsafe_load": ("Unsafe deserialization", "high",
        "User input reaches yaml.unsafe_load().", "CWE-502", "first"),
}
_DESERIALIZE_MODS = {"pickle", "cpickle", "marshal", "jsonpickle", "dill", "yaml"}


def _callee_name(func: ast.AST) -> tuple[str, str]:
    """Return ``(attr_name, root_module)`` for a call target."""
    if isinstance(func, ast.Attribute):
        root = func.value.id if isinstance(func.value, ast.Name) else ""
        return func.attr, root
    if isinstance(func, ast.Name):
        return func.id, ""
    return "", ""


def _is_source(node: ast.AST) -> bool:
    """True if *node* is a `request.<source>` style expression."""
    cur = node
    # Unwrap calls like request.args.get('x') / request.get_json()
    while isinstance(cur, ast.Call):
        cur = cur.func
    while isinstance(cur, ast.Subscript):
        cur = cur.value
    seen_attr = False
    while isinstance(cur, ast.Attribute):
        if cur.attr in _SOURCE_ATTRS:
            seen_attr = True
        cur = cur.value
    if isinstance(cur, ast.Name):
        if cur.id in _SOURCE_ROOTS:
            return True
        if cur.id in _SOURCE_ROOTS and seen_attr:
            return True
    return seen_attr and _root_is_request(node)


def _root_is_request(node: ast.AST) -> bool:
    cur = node
    while isinstance(cur, (ast.Call, ast.Subscript, ast.Attribute)):
        cur = cur.func if isinstance(cur, ast.Call) else (
            cur.value if isinstance(cur, (ast.Subscript, ast.Attribute)) else cur)
    return isinstance(cur, ast.Name) and cur.id in _SOURCE_ROOTS


class _TaintVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.tainted: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._expr_tainted(node.value, set()):
            for tgt in node.targets:
                self._mark(tgt)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and self._expr_tainted(node.value, set()):
            self._mark(node.target)
        self.generic_visit(node)

    def _mark(self, target: ast.AST) -> None:
        if isinstance(target, ast.Name):
            self.tainted.add(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._mark(elt)

    def _expr_tainted(self, node: ast.AST, _seen) -> bool:
        return expr_tainted(node, self.tainted)


def expr_tainted(node: ast.AST, tainted: set[str]) -> bool:
    """True if *node* references a tainted name or a request source."""
    if node is None:
        return False
    if _is_source(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.JoinedStr):  # f-string
        return any(expr_tainted(v, tainted) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return expr_tainted(node.value, tainted)
    if isinstance(node, ast.BinOp):  # a + b, a % b
        return expr_tainted(node.left, tainted) or expr_tainted(node.right, tainted)
    if isinstance(node, ast.Call):
        name, _ = _callee_name(node.func)
        if name == "format" and isinstance(node.func, ast.Attribute):
            if expr_tainted(node.func.value, tainted):
                return True
        if name in {"str", "repr", "format"}:
            return any(expr_tainted(a, tainted) for a in node.args)
        return False
    if isinstance(node, ast.Subscript):
        return expr_tainted(node.value, tainted)
    if isinstance(node, (ast.Attribute,)):
        return expr_tainted(node.value, tainted)
    return False


def _is_string_building(node: ast.AST) -> bool:
    """True if arg0 is an f-string / concat / %-format / .format() call."""
    if isinstance(node, (ast.JoinedStr, ast.BinOp)):
        return True
    if isinstance(node, ast.Call):
        name, _ = _callee_name(node.func)
        return name == "format"
    return False


def analyze_python(name: str, source: str) -> tuple[list[Finding], list[str]]:
    """Return ``(findings, routes)`` for one Python source file."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return [], []
    lines = source.splitlines()
    tv = _TaintVisitor()
    tv.visit(tree)
    tainted = tv.tainted
    findings: list[Finding] = []
    routes: list[str] = []
    seen_lines: set[int] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _check_sink(node, tainted, name, lines, findings, seen_lines)
        routes.extend(_routes_from(node))
    return findings, routes


def _check_sink(node: ast.Call, tainted: set[str], name: str, lines: list[str],
                findings: list[Finding], seen_lines: set[int]) -> None:
    callee, root = _callee_name(node.func)
    spec = _SINKS.get(callee)
    if spec is None:
        return
    category, conf, why, cwe, which = spec
    args = list(node.args)
    hit = False
    if which == "first":
        hit = bool(args) and expr_tainted(args[0], tainted)
        if callee == "loads" and root.lower() not in _DESERIALIZE_MODS:
            hit = False
    elif which == "any":
        hit = any(expr_tainted(a, tainted) for a in args)
    elif which == "sql":
        hit = bool(args) and _is_string_building(args[0]) and expr_tainted(args[0], tainted)
    elif which == "subprocess":
        shell_true = any(isinstance(k.value, ast.Constant) and k.value.value is True
                         for k in node.keywords if k.arg == "shell")
        tainted_arg = any(expr_tainted(a, tainted) for a in args)
        hit = tainted_arg and (shell_true or True)  # flag even without shell; note shell
        if tainted_arg and not shell_true:
            conf = "low"
    if not hit:
        return
    line_no = getattr(node, "lineno", 0)
    if line_no in seen_lines:
        return
    seen_lines.add(line_no)
    snippet = lines[line_no - 1].strip()[:170] if 0 < line_no <= len(lines) else callee + "(...)"
    findings.append(Finding(
        category, conf, f"{name}:{line_no}", snippet,
        why + " (taint-tracked from a request source).",
        "Confirm reachability and any filtering between source and sink.",
        origin="source", cwe=cwe))


def _routes_from(node: ast.AST) -> list[str]:
    """Extract Flask/FastAPI-style routes from a decorated function."""
    out: list[str] = []
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return out
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        attr, _ = _callee_name(dec.func)
        if attr not in {"route", "get", "post", "put", "delete", "patch"}:
            continue
        path = ""
        for arg in dec.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                path = arg.value
                break
        methods = []
        for kw in dec.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                methods = [e.value for e in kw.value.elts
                           if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        if path:
            verb = attr.upper() if attr != "route" else (",".join(methods) or "GET")
            out.append(f"{verb} {path}")
    return out
