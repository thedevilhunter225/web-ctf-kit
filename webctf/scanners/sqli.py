"""SQL injection scanner: error-based, boolean-based, and time-based detection."""
from __future__ import annotations

import difflib
import re

from ..core.evidence import Finding, Hypothesis, Parameter
from ..payloads import sqli as payloads
from .base import ScanContext, Scanner, register

SQL_ERRORS = re.compile(
    r"(?:SQL syntax|SQLSTATE\[|SQLSTATE\b|sqlite3?\.(?:OperationalError|ProgrammingError)|"
    r"unrecognized token:|near \".*\": syntax error|near '.*': syntax error|"
    r"mysql_fetch|mysqli?_\w+|psycopg2\.errors|PostgreSQL.*ERROR|"
    r"ORA-\d{5}|ODBC SQL Server Driver|syntax error at or near|"
    r"Unclosed quotation mark|quoted string not properly terminated|"
    r"You have an error in your SQL syntax)",
    flags=re.IGNORECASE,
)


def _similar(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()


@register
class SQLiScanner(Scanner):
    name = "sqli"
    category = "SQL injection"
    description = "Error-based, boolean-based and time-based SQL injection detection."

    def scan(self, param: Parameter, ctx: ScanContext) -> None:
        value = param.fields.get(param.name) or "1"
        base, _ = ctx.trial(param, value, category=self.category)
        if base is None:
            return
        base_text, base_time = base.text, base.elapsed
        base_error = bool(SQL_ERRORS.search(base_text))

        if self._error_based(param, ctx, value, base_text, base_error):
            return
        if self._boolean_based(param, ctx, value, base_text):
            return
        self._time_based(param, ctx, value, base_time)

    def _error_based(self, param, ctx, value, base_text, base_error) -> bool:
        if base_error:
            return False
        for q in payloads.ERROR_PROBES[:5]:
            if not ctx.budget.allows():
                return False
            resp, attempt = ctx.trial(param, value + q, category=self.category,
                                      expected="database error")
            if resp is None:
                return False
            m = SQL_ERRORS.search(resp.text)
            if m and not SQL_ERRORS.search(base_text):
                if attempt:
                    attempt.supports = True
                    attempt.confidence = 0.7
                    attempt.note = "DB error triggered by quote"
                ctx.result.add_finding(Finding(
                    "SQL injection (error-based)", "high", param.description,
                    "Database error provoked: " + m.group(0),
                    "A single quote produced a database error absent from the baseline.",
                    "Use --solve to attempt bounded UNION-based data extraction.",
                    origin="dynamic", payload=value + q, cwe="CWE-89"))
                ctx.result.add_hypothesis(Hypothesis(
                    "SQLi extraction", param.description,
                    "Error-based SQLi; column count discoverable via ORDER BY.",
                    priority=80, source="dynamic", scanner="sqli"))
                ctx.queue_solve("sqli", param, technique="error")
                return True
        return False

    def _boolean_based(self, param, ctx, value, base_text) -> bool:
        for true_p, false_p in payloads.BOOLEAN_PAIRS:
            if not ctx.budget.allows(2):
                return False
            t_resp, t_att = ctx.trial(param, value + true_p, category=self.category,
                                      expected="TRUE condition ~ baseline")
            f_resp, f_att = ctx.trial(param, value + false_p, category=self.category,
                                      expected="FALSE condition differs")
            if t_resp is None or f_resp is None:
                return False
            if SQL_ERRORS.search(t_resp.text) or SQL_ERRORS.search(f_resp.text):
                continue
            st = _similar(t_resp.text, base_text)
            sf = _similar(f_resp.text, base_text)
            differ = _similar(t_resp.text, f_resp.text)
            signal = abs(st - sf)
            if signal > 0.15 and differ < 0.97:
                if t_att:
                    t_att.supports = True
                    t_att.confidence = min(0.9, 0.5 + signal)
                    t_att.note = f"boolean delta sim(T)={st:.2f} sim(F)={sf:.2f}"
                ctx.result.add_finding(Finding(
                    "SQL injection (boolean-based)", "high", param.description,
                    f"TRUE/FALSE conditions change the response (Δsimilarity={signal:.2f}).",
                    "Different responses for logically true vs false SQL conditions "
                    "indicate the input is evaluated inside a query.",
                    "Use --solve to attempt bounded data extraction.",
                    origin="dynamic", payload=value + true_p, cwe="CWE-89"))
                ctx.result.add_hypothesis(Hypothesis(
                    "SQLi extraction", param.description,
                    "Boolean-based blind SQLi; extraction via bit/char oracle.",
                    priority=78, source="dynamic", scanner="sqli"))
                ctx.queue_solve("sqli", param, technique="boolean")
                return True
        return False

    def _time_based(self, param, ctx, value, base_time) -> bool:
        threshold = max(2.5, base_time + 2.0)
        for probe in payloads.TIME_PROBES[:3]:
            if not ctx.budget.allows(2):
                return False
            slow, att = ctx.trial(param, value + probe.format(s=3), category=self.category,
                                  expected="~3s delay")
            if slow is None:
                return False
            if slow.elapsed < threshold:
                continue
            fast, _ = ctx.trial(param, value + probe.format(s=1), category=self.category,
                                expected="~1s delay")
            if fast is not None and fast.elapsed < slow.elapsed - 1.0:
                if att:
                    att.supports = True
                    att.confidence = 0.8
                    att.note = f"delay scaled {slow.elapsed:.1f}s vs {fast.elapsed:.1f}s"
                ctx.result.add_finding(Finding(
                    "SQL injection (time-based blind)", "high", param.description,
                    f"Injected SLEEP produced {slow.elapsed:.1f}s vs {fast.elapsed:.1f}s delay.",
                    "Response time scales with an injected time function, indicating "
                    "blind SQL injection.",
                    "Extraction is slow; prefer boolean/UNION if available.",
                    origin="dynamic", payload=value + probe.format(s=3), cwe="CWE-89"))
                ctx.queue_solve("sqli", param, technique="time")
                return True
        return False
