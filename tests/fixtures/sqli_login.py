"""String-context SQL injection over SQLite (error + UNION). TEST FIXTURE ONLY.

``/user?id=`` is concatenated straight into a quoted string context, so a single
quote raises a (surfaced) SQLite error and a UNION SELECT reflects into the page.
The flag lives in a ``secrets`` table reachable by UNION extraction.
"""
from __future__ import annotations

import atexit
import sqlite3
import threading

from .wsgi_common import first, query, respond

_HOME = ('<html><body><h2>Users</h2>'
         '<a href="/user?id=1">user 1</a> <a href="/user?id=2">user 2</a>')


def make_app(flag: str = "flag{sqli_union_demo}"):
    # A single in-memory DB shared across the threaded server, guarded by a lock
    # (one connection avoids per-request open/close churn and resource warnings).
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.execute("CREATE TABLE users(id TEXT, username TEXT, password TEXT)")
    con.executemany("INSERT INTO users VALUES(?,?,?)",
                    [("1", "alice", "alpha"), ("2", "bob", "bravo")])
    con.execute("CREATE TABLE secrets(flag TEXT)")
    con.execute("INSERT INTO secrets VALUES(?)", (flag,))
    con.commit()
    atexit.register(con.close)
    lock = threading.Lock()

    def app(environ, start_response):
        if environ.get("PATH_INFO", "/") != "/user":
            return respond(start_response, _HOME + "home</body></html>")
        uid = first(query(environ), "id", "1")
        sql = "SELECT id, username FROM users WHERE id = '%s'" % uid  # vulnerable
        try:
            with lock:
                rows = con.execute(sql).fetchall()
            out = "".join("User: %s<br>" % r[1] for r in rows) or "no such user"
        except Exception as exc:
            out = "DB error: %s.%s: %s" % (type(exc).__module__, type(exc).__name__, exc)
        return respond(start_response, _HOME + out + "</body></html>")
    return app
