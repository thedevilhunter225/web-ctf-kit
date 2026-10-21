"""Serve one bundled, deliberately-vulnerable fixture so you can try the solver.

    python examples/vuln_lab.py ssti            # or: sqli lfi cmdi xss bot
    # then, in another terminal:
    webctf solve --url http://127.0.0.1:8099/ --ack-authorized --no-paths

These apps are INTENTIONALLY insecure and bind to 127.0.0.1 only. Never deploy
them or expose them to a network.
"""
import os
import sys
from wsgiref.simple_server import make_server

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tests"))

from fixtures import (  # noqa: E402
    admin_bot, cmdi_ping, lfi_viewer, sqli_login, ssti_eval, xss_blacklist,
)

APPS = {
    "ssti": ssti_eval, "sqli": sqli_login, "lfi": lfi_viewer,
    "cmdi": cmdi_ping, "xss": xss_blacklist, "bot": admin_bot,
}


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else "ssti"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8099
    if name not in APPS:
        print(f"Unknown fixture '{name}'. Choose: {', '.join(APPS)}")
        return 2
    app = APPS[name].make_app()
    print(f"Serving '{name}' at http://127.0.0.1:{port}/  (Ctrl+C to stop)")
    print(f"Try:  webctf solve --url http://127.0.0.1:{port}/ --ack-authorized --no-paths")
    try:
        make_server("127.0.0.1", port, app).serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
