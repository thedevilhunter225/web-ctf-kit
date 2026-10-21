"""Web CTF Kit command-line interface.

Zero third-party dependencies (argparse + the standard library) so it runs on a
bare Kali/Python 3.10+ install with no setup. Rich is used automatically for
colour when present, but is never required. No AI, LLM or cloud calls are made.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core.config import RunConfig
from .core.engine import run as run_pipeline


def positive_int(text: str) -> int:
    number = int(text)
    if not (1 <= number <= 100000):
        raise argparse.ArgumentTypeError("Must be in the range 1..100000")
    return number


def nonneg_int(text: str) -> int:
    number = int(text)
    if not (0 <= number <= 100000):
        raise argparse.ArgumentTypeError("Must be in the range 0..100000")
    return number


def bounded_float(text: str) -> float:
    number = float(text)
    if not (0 <= number <= 600):
        raise argparse.ArgumentTypeError("Must be between 0 and 600")
    return number


def parse_headers(items: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in items:
        if ":" not in value:
            raise ValueError("Header must be NAME:VALUE")
        k, v = value.split(":", 1)
        if not k.strip():
            raise ValueError("Empty header name")
        headers[k.strip()] = v.strip()
    return headers


def _csv(text: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in text.split(",") if x.strip())


def add_report_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--output", metavar="DIR", help="Write findings.json and report.md")
    p.add_argument("--json", action="store_true", help="Print full JSON instead of a summary")
    p.add_argument("--quiet", action="store_true", help="Suppress the banner")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colour")
    p.add_argument("--verbose", action="store_true", help="Show every finding")


def add_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--max-pages", default=20, type=positive_int, help="Crawl page cap (default 20)")
    p.add_argument("--max-tests", default=150, type=nonneg_int, help="Active probe cap (default 150)")
    p.add_argument("--max-time", default=0, type=bounded_float, help="Overall time budget seconds (0=off)")
    p.add_argument("--timeout", default=8, type=bounded_float, help="Per-request timeout (default 8)")
    p.add_argument("--delay", default=0.1, type=bounded_float, help="Delay between requests (default 0.1)")
    p.add_argument("--cookie", default="", help="Cookie header (never written to reports)")
    p.add_argument("--header", action="append", default=[], metavar="NAME:VALUE",
                   help="Extra HTTP header (repeatable)")
    p.add_argument("--guess", action="store_true", help="Also test common parameter names")
    p.add_argument("--no-paths", action="store_true", help="Disable common-path enumeration")
    p.add_argument("--only", type=_csv, default=(), metavar="a,b", help="Run only these scanners")
    p.add_argument("--skip", type=_csv, default=(), metavar="a,b", help="Skip these scanners")
    p.add_argument("--flag-regex", default="", help="Custom flag regex (added to defaults)")
    p.add_argument("--flag-only", action="store_true", help="Use only --flag-regex, not defaults")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webctf",
        description="Deterministic, no-AI toolkit for authorized Web CTF challenges.",
        epilog="Only test CTF instances, local labs or targets you are authorized to assess.")
    parser.add_argument("--version", action="version", version=f"webctf {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    solve = sub.add_parser("solve", help="One command: source + recon + probes + flag retrieval")
    solve.add_argument("--url", required=True, help="Authorized challenge URL (one origin)")
    solve.add_argument("--source", help="Optional distributed source (ZIP/TAR/dir/file)")
    solve.add_argument("--ack-authorized", action="store_true", help="Confirm you may test this target")
    solve.add_argument("--no-solve", action="store_true", help="Detect only; no flag-retrieval attempts")
    add_scan_args(solve)
    add_report_args(solve)

    scan = sub.add_parser("scan", help="Active, scope-limited vulnerability probes (no auto-solve)")
    scan.add_argument("--url", required=True)
    scan.add_argument("--ack-authorized", action="store_true")
    add_scan_args(scan)
    add_report_args(scan)

    recon = sub.add_parser("recon", help="Passive crawl + fingerprint + flag spotting (no payloads)")
    recon.add_argument("--url", required=True)
    add_scan_args(recon)
    add_report_args(recon)

    analyze = sub.add_parser("analyze", help="Offline source analysis (ZIP/TAR/dir/file)")
    analyze.add_argument("--source", help="Source path")
    analyze.add_argument("path", nargs="?", help="Source path (positional alternative)")
    analyze.add_argument("--flag-regex", default="")
    analyze.add_argument("--flag-only", action="store_true")
    add_report_args(analyze)
    # `source` is kept as an alias of `analyze`.
    source = sub.add_parser("source", help="Alias of analyze")
    source.add_argument("--source")
    source.add_argument("path", nargs="?")
    source.add_argument("--flag-regex", default="")
    source.add_argument("--flag-only", action="store_true")
    add_report_args(source)

    report = sub.add_parser("report", help="Pretty-print a saved findings.json")
    report.add_argument("--input", required=True, help="Path to findings.json")
    report.add_argument("--no-color", action="store_true")

    gui = sub.add_parser("gui", help="Launch the interactive terminal UI (menu-driven)")
    gui.add_argument("--no-color", action="store_true")
    tui = sub.add_parser("tui", help="Alias of gui")
    tui.add_argument("--no-color", action="store_true")

    sub.add_parser("doctor", help="Check the environment and optional dependencies")

    plugins = sub.add_parser("plugins", help="List available scanner plugins")
    plugins.add_argument("--json", action="store_true")

    bot = sub.add_parser("bot", help="Submit one URL to a CTF admin-report endpoint")
    bot.add_argument("--url", required=True, help="Challenge URL")
    bot.add_argument("--report-path", default="/report")
    bot.add_argument("--report-field", default="url")
    bot.add_argument("--visit-url", help="Complete URL for the bot to visit")
    bot.add_argument("--bot-base", help="Internal bot base URL (e.g. http://127.0.0.1:8000/)")
    bot.add_argument("--inject-param", help="Query parameter to inject a payload into")
    bot.add_argument("--payload", help="Literal payload")
    bot.add_argument("--payload-file", help="Read payload from a UTF-8 file")
    bot.add_argument("--timeout", type=bounded_float, default=12)
    bot.add_argument("--cookie", default="")
    bot.add_argument("--ack-authorized", action="store_true", required=True)
    # --- auto cookie-exfil capture mode ---
    bot.add_argument("--capture", action="store_true",
                     help="Stand up a local listener, send a cookie-exfil XSS via /report, "
                          "and print the captured flag")
    bot.add_argument("--listen-host", default="0.0.0.0", help="Capture listener bind host")
    bot.add_argument("--listen-port", type=int, default=0, help="Capture listener port (0=auto)")
    bot.add_argument("--listener-url", default="",
                     help="Exfil URL the bot should reach (e.g. your public/tunnel URL). "
                          "Defaults to this host for local 127.0.0.1 challenges.")
    bot.add_argument("--xss-payload", default="",
                     help="Custom XSS payload; {URL} and {JS} are substituted")
    bot.add_argument("--xss-tag", default="h1", help="Carrier tag for the default payload")
    bot.add_argument("--exfil", default="cookie", choices=["cookie", "location", "storage", "body"],
                     help="What the payload exfiltrates (default: cookie)")
    bot.add_argument("--wait", type=bounded_float, default=15, help="Seconds to wait for the callback")
    bot.add_argument("--flag-regex", default="", help="Custom flag regex for the callback")
    bot.add_argument("--flag-only", action="store_true")

    jwt = sub.add_parser("jwt", help="Decode / forge / crack a JWT (offline)")
    jwt.add_argument("token", help="JWT string")
    jwt.add_argument("--forge-none", action="store_true", help="Forge an alg:none token")
    jwt.add_argument("--secret", help="Re-sign with this HS256 secret")
    jwt.add_argument("--crack", action="store_true", help="Try a small HS256 secret wordlist")
    jwt.add_argument("--wordlist", help="Secret wordlist file (one per line)")
    jwt.add_argument("--set", action="append", default=[], metavar="claim=value",
                     help="Override a claim (repeatable)")
    return parser


def _config_from(args: argparse.Namespace, *, active: bool, solve: bool) -> RunConfig:
    return RunConfig(
        active=active, solve=solve,
        max_pages=args.max_pages, max_tests=args.max_tests, max_time=args.max_time,
        timeout=args.timeout, delay=args.delay, cookie=args.cookie,
        headers=parse_headers(args.header), guess_params=args.guess,
        enum_paths=not args.no_paths, only=args.only, skip=args.skip,
        flag_regex=args.flag_regex, flag_only=args.flag_only,
        output_dir=args.output or "", quiet=args.quiet, no_color=args.no_color,
        verbose=args.verbose,
    )


def _emit(result, args) -> int:
    from .reporting import save_report, print_summary, print_banner
    if args.output:
        j, m = save_report(result, args.output)
        print(f"Reports written: {j} | {m}", file=sys.stderr)
    if getattr(args, "json", False):
        print(json.dumps(result.as_dict(), indent=2, ensure_ascii=False))
    else:
        if not getattr(args, "quiet", False):
            print_banner(args.no_color)
        print_summary(result, no_color=args.no_color, verbose=args.verbose)
    live = bool(result.visited) or result.mode == "source"
    if result.mode in ("recon", "scan", "solve") and not any(
            not v.startswith("source:") for v in result.visited):
        print("Warning: the live target returned no readable pages.", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command in ("solve", "scan", "recon"):
            return _run_dynamic(args)
        if args.command in ("analyze", "source"):
            from .analyzers import analyze
            path = args.source or args.path
            if not path:
                raise ValueError("Provide a source path (--source or positional)")
            result = analyze(path, flag_regex=args.flag_regex, flag_only=args.flag_only)
            return _emit(result, args)
        if args.command == "report":
            from .reporting.console import print_result_dict
            from .reporting.json_report import load_result
            print_result_dict(load_result(args.input), no_color=args.no_color)
            return 0
        if args.command in ("gui", "tui"):
            from .tui import run_tui
            return run_tui(no_color=args.no_color)
        if args.command == "doctor":
            return _doctor()
        if args.command == "plugins":
            return _plugins(args.json)
        if args.command == "bot":
            return _bot(args)
        if args.command == "jwt":
            return _jwt(args)
        raise ValueError("Unknown command")
    except (ValueError, FileNotFoundError, ConnectionError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def _run_dynamic(args) -> int:
    active = args.command in ("scan", "solve")
    solve = args.command == "solve" and not args.no_solve
    if active and not args.ack_authorized:
        raise ValueError(f"'{args.command}' sends active probes and requires --ack-authorized")
    config = _config_from(args, active=active, solve=solve)
    source = getattr(args, "source", None)
    result = run_pipeline(args.url, config, source=source)
    return _emit(result, args)


def _doctor() -> int:
    import importlib
    import platform
    from .scanners import all_scanners
    print("webctf doctor\n" + "-" * 40)
    print(f"webctf version : {__version__}")
    print(f"python         : {platform.python_version()} ({sys.platform})")
    ok = sys.version_info >= (3, 10)
    print(f"python >= 3.10 : {'yes' if ok else 'NO - upgrade required'}")
    print("\nOptional dependencies (none required for core operation):")
    for mod, why in [("rich", "prettier output"), ("playwright", "browser automation / XSS confirmation"),
                     ("requests", "not required; stdlib urllib is used"),
                     ("flask", "realistic test fixtures"), ("jinja2", "realistic SSTI fixtures")]:
        try:
            importlib.import_module(mod)
            print(f"  [ok]      {mod:12} ({why})")
        except Exception:
            print(f"  [missing] {mod:12} ({why})")
    print(f"\nRegistered scanners: {len(all_scanners())}")
    for s in sorted(all_scanners(), key=lambda x: x.name):
        exp = " (experimental)" if s.experimental else ""
        print(f"  - {s.name:11} {s.category}{exp}")
    print("\nNo AI/LLM runtime. All analysis is deterministic Python.")
    return 0


def _plugins(as_json: bool) -> int:
    from .scanners import all_scanners
    data = [{"name": s.name, "category": s.category, "scope": s.scope,
             "experimental": s.experimental, "description": s.description}
            for s in sorted(all_scanners(), key=lambda x: x.name)]
    if as_json:
        print(json.dumps(data, indent=2))
        return 0
    print("Available scanner plugins:\n")
    for d in data:
        exp = "  [experimental]" if d["experimental"] else ""
        print(f"  {d['name']:11} [{d['scope']}] {d['category']}{exp}")
        print(f"              {d['description']}")
    print("\nAdd your own by subclassing webctf.scanners.base.Scanner and "
          "decorating it with @register (see README).")
    return 0


def _bot(args) -> int:
    from .browser.bot import build_visit_url, submit_report
    if args.capture:
        return _bot_capture(args)
    payload = None
    if args.payload_file and args.payload is not None:
        raise ValueError("Use --payload or --payload-file, not both")
    if args.payload_file:
        with open(args.payload_file, "r", encoding="utf-8") as fh:
            payload = fh.read()
    elif args.payload is not None:
        payload = args.payload
    visit = build_visit_url(visit_url=args.visit_url, bot_base=args.bot_base,
                            inject_param=args.inject_param, payload=payload)
    print(f"Submitting one visit URL to {args.report_path} on {args.url}")
    reply = submit_report(args.url, visit, report_path=args.report_path,
                          report_field=args.report_field, timeout=args.timeout,
                          cookie=args.cookie)
    print(f"HTTP {reply.status}\n{reply.text[:2000]}")
    if 200 <= reply.status < 300:
        print("The report endpoint accepted the URL; actual bot execution is unverified.")
    return 0 if reply.status < 400 else 1


def _bot_capture(args) -> int:
    from .browser.capture import capture_and_exfil
    from .flags.engine import compile_patterns
    if not args.bot_base or not args.inject_param:
        raise ValueError("--capture requires --bot-base and --inject-param")
    patterns = compile_patterns(args.flag_regex, args.flag_only)
    result = capture_and_exfil(
        args.url, bot_base=args.bot_base, inject_param=args.inject_param,
        report_path=args.report_path, report_field=args.report_field,
        listen_host=args.listen_host, listen_port=args.listen_port,
        listener_url=args.listener_url, xss_payload=args.xss_payload,
        xss_tag=args.xss_tag, exfil_what=args.exfil, wait=args.wait,
        timeout=args.timeout, cookie=args.cookie, flag_patterns=patterns)
    print(f"[*] Exfil URL for the bot : {result.exfil_url}")
    print(f"[*] XSS payload           : {result.payload}")
    print(f"[*] Submitted to {args.report_path} -> HTTP {result.report_status}")
    if result.report_status >= 400:
        print(f"    report said: {result.report_body[:200]}")
    if result.flags:
        for h in result.hits:
            if any(f in h.blob() for f in result.flags):
                print(f"[+] Callback from {h.client}: {h.method} /?{h.query[:120]}")
                break
        print(f"\n[+] FLAG: {result.flags[0]}")
        return 0
    print(f"[-] No flag in the callback within {args.wait:.0f}s "
          f"({len(result.hits)} request(s) captured).")
    for h in result.hits[:5]:
        print(f"    {h.method} {h.path}?{h.query[:120]} from {h.client}")
    print("    Tips: ensure the bot can reach --listener-url; a filtered tag may need "
          "--xss-payload; raise --wait.")
    return 1


def _jwt(args) -> int:
    from .exploits import jwt_forge
    info = jwt_forge.decode(args.token)
    print("Header :", json.dumps(info["header"]))
    print("Payload:", json.dumps(info["payload"]))
    claims = {}
    for item in args.set:
        if "=" not in item:
            raise ValueError("--set expects claim=value")
        k, v = item.split("=", 1)
        try:
            claims[k] = json.loads(v)
        except json.JSONDecodeError:
            claims[k] = v
    if args.crack:
        words = None
        if args.wordlist:
            with open(args.wordlist, "r", encoding="utf-8", errors="replace") as fh:
                words = [w.strip() for w in fh if w.strip()]
        secret = jwt_forge.crack_hs256(args.token, words)
        print("Cracked secret:", secret if secret else "(not found in wordlist)")
        if secret and claims:
            print("Forged (HS256):", jwt_forge.forge_hs256(args.token, secret, claims))
    if args.forge_none:
        print("Forged (alg:none):", jwt_forge.forge_none(args.token, claims))
    if args.secret:
        print("Forged (HS256):", jwt_forge.forge_hs256(args.token, args.secret, claims))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
