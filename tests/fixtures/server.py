"""Run a WSGI app on an ephemeral localhost port in a background thread."""
from __future__ import annotations

import threading
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class _QuietHandler(WSGIRequestHandler):
    def log_message(self, *args):  # silence request logging in tests
        pass


class ServedApp:
    """Context manager yielding a running server with ``.url`` on 127.0.0.1."""

    def __init__(self, app):
        self.httpd = make_server("127.0.0.1", 0, app,
                                 server_class=_ThreadingWSGIServer,
                                 handler_class=_QuietHandler)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> "ServedApp":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(2)
