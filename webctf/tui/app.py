"""A menu-driven terminal UI. No third-party dependencies.

Wraps the same engine the CLI uses, with guided prompts, an authorization gate for
active modes, and a live progress line while a scan runs. Designed to degrade
gracefully when not attached to a TTY (e.g. under tests): no screen clears or
animation, just linear prompts and output.
"""
from __future__ import annotations

import sys
import threading
import time

from .. import __version__
from ..core.config import RunConfig
from ..core.engine import run as run_pipeline
from ..core.evidence import Result

_C = {"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "green": "\033[32m",
      "red": "\033[31m", "yellow": "\033[33m", "cyan": "\033[36m", "mag": "\033[35m"}


def _tty() -> bool:
    try:
        return sys.stdout.isatty() and sys.stdin.isatty()
    except Exception:
        return False


class UI:
    def __init__(self, no_color: bool = False):
        self.color = not no_color and _tty()

    def c(self, text: str, color: str) -> str:
        if not self.color or color not in _C:
            return text
        return f"{_C[color]}{text}{_C['reset']}"

    def clear(self) -> None:
        if self.color:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()

    def banner(self) -> None:
        self.clear()
        bar = "=" * 62
        print(self.c(bar, "cyan"))
        print(self.c(f"  WEB CTF SOLVER  -  terminal UI  -  v{__version__}", "bold"))
        print(self.c("  deterministic - no-AI - authorized CTF targets only", "dim"))
        print(self.c(bar, "cyan"))

    # -- prompts -------------------------------------------------------
    def ask(self, label: str, default: str = "") -> str:
        # EOFError propagates so a closed stdin cleanly quits the menu loop.
        suffix = self.c(f" [{default}]", "dim") if default else ""
        value = input(f"{self.c('?', 'cyan')} {label}{suffix}: ").strip()
        return value or default

    def ask_bool(self, label: str, default: bool = False) -> bool:
        d = "Y/n" if default else "y/N"
        value = self.ask(f"{label} ({d})", "")
        if not value:
            return default
        return value[0].lower() == "y"

    def ask_int(self, label: str, default: int) -> int:
        value = self.ask(label, str(default))
        try:
            return int(value)
        except ValueError:
            return default

    def pause(self) -> None:
        try:
            input(self.c("\nPress Enter to return to the menu...", "dim"))
        except EOFError:
            pass


MENU = [
    ("1", "Solve", "full auto: recon + source + probes + flag retrieval"),
    ("2", "Scan", "active vulnerability probes (no auto-solve)"),
    ("3", "Recon", "passive crawl + fingerprint (no payloads)"),
    ("4", "Analyze source", "offline ZIP/TAR/dir/file analysis"),
    ("5", "Admin-bot capture", "auto cookie-exfil via /report"),
    ("6", "JWT tool", "decode / forge / crack a token (offline)"),
    ("7", "Doctor", "environment & scanner check"),
    ("8", "Plugins", "list scanner plugins"),
    ("q", "Quit", ""),
]


def run_tui(no_color: bool = False) -> int:
    ui = UI(no_color=no_color)
    while True:
        ui.banner()
        print()
        for key, name, desc in MENU:
            tag = ui.c(f"  {key})", "cyan")
            print(f"{tag} {ui.c(name, 'bold'):<28} {ui.c(desc, 'dim')}")
        print()
        try:
            choice = ui.ask("Choose", "1").lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return 0
        try:
            if choice in ("q", "quit", "exit", "0"):
                print(ui.c("Bye. Good luck - flag responsibly.", "green"))
                return 0
            if choice == "1":
                _flow_dynamic(ui, "solve")
            elif choice == "2":
                _flow_dynamic(ui, "scan")
            elif choice == "3":
                _flow_dynamic(ui, "recon")
            elif choice == "4":
                _flow_analyze(ui)
            elif choice == "5":
                _flow_bot_capture(ui)
            elif choice == "6":
                _flow_jwt(ui)
            elif choice == "7":
                _flow_doctor(ui)
            elif choice == "8":
                _flow_plugins(ui)
            else:
                print(ui.c("Unknown choice.", "yellow"))
                ui.pause()
        except EOFError:
            return 0  # stdin closed (piped input ended) -> quit cleanly
        except KeyboardInterrupt:
            print(ui.c("\n(cancelled)", "yellow"))
            ui.pause()
        except Exception as exc:  # keep the menu alive on any flow error
            print(ui.c(f"\nError: {exc}", "red"))
            ui.pause()


def _advanced(ui: UI, config: RunConfig) -> RunConfig:
    if not ui.ask_bool("Configure advanced options", False):
        return config
    config.max_pages = ui.ask_int("Max pages", config.max_pages)
    config.max_tests = ui.ask_int("Max active tests", config.max_tests)
    config.delay = float(ui.ask(f"Delay between requests (s)", str(config.delay)) or config.delay)
    config.timeout = float(ui.ask("Per-request timeout (s)", str(config.timeout)) or config.timeout)
    config.flag_regex = ui.ask("Custom flag regex (blank = defaults)", config.flag_regex)
    config.cookie = ui.ask("Session cookie header (blank = none)", config.cookie)
    config.guess_params = ui.ask_bool("Guess common parameter names", config.guess_params)
    config.enum_paths = ui.ask_bool("Enumerate common paths", config.enum_paths)
    return config


def _flow_dynamic(ui: UI, mode: str) -> None:
    ui.banner()
    print(ui.c(f"\n  {mode.upper()}\n", "bold"))
    url = ui.ask("Target URL (e.g. http://127.0.0.1:8000/)")
    if not url:
        print(ui.c("A URL is required.", "yellow"))
        return ui.pause()
    source = ""
    if mode == "solve":
        source = ui.ask("Source archive/dir (optional, blank to skip)")
    active = mode in ("scan", "solve")
    if active:
        print(ui.c("\n  Active probing sends test payloads to the target.", "yellow"))
        if not ui.ask_bool("I am authorized to test this target", False):
            print(ui.c("Authorization not confirmed - aborting.", "yellow"))
            return ui.pause()
    config = RunConfig(active=active, solve=(mode == "solve"))
    config = _advanced(ui, config)
    result = _run_with_progress(ui, url, config, source or None, mode)
    _render(ui, result)
    ui.pause()


def _flow_analyze(ui: UI) -> None:
    from ..analyzers import analyze
    ui.banner()
    print(ui.c("\n  ANALYZE SOURCE (offline)\n", "bold"))
    path = ui.ask("Source path (ZIP / TAR / directory / file)")
    if not path:
        return ui.pause()
    flag_regex = ui.ask("Custom flag regex (blank = defaults)", "")
    print(ui.c("\nanalyzing...", "dim"))
    result = analyze(path, flag_regex=flag_regex)
    _render(ui, result)
    ui.pause()


def _flow_bot_capture(ui: UI) -> None:
    from ..browser.capture import capture_and_exfil
    ui.banner()
    print(ui.c("\n  ADMIN-BOT COOKIE EXFIL\n", "bold"))
    url = ui.ask("Challenge URL")
    if not url:
        return ui.pause()
    bot_base = ui.ask("Bot base URL (the URL the bot visits)", url)
    inject = ui.ask("Parameter to inject the payload into", "html_input")
    if not ui.ask_bool("I am authorized to test this target", False):
        print(ui.c("Authorization not confirmed - aborting.", "yellow"))
        return ui.pause()
    listener_url = ui.ask("Exfil URL the bot can reach (blank = auto for localhost)", "")
    wait = float(ui.ask("Seconds to wait for the callback", "15") or 15)
    print(ui.c("\nstanding up listener and reporting payload...", "dim"))
    res = capture_and_exfil(url, bot_base=bot_base, inject_param=inject,
                            listener_url=listener_url, wait=wait)
    print(f"\n  Exfil URL : {res.exfil_url}")
    print(f"  Payload   : {res.payload}")
    print(f"  /report   : HTTP {res.report_status}")
    if res.flags:
        print("\n  " + ui.c(f"FLAG: {res.flags[0]}", "green"))
    else:
        print(ui.c(f"\n  No flag in callback ({len(res.hits)} request(s) captured).", "yellow"))
    ui.pause()


def _flow_jwt(ui: UI) -> None:
    from ..exploits import jwt_forge
    import json
    ui.banner()
    print(ui.c("\n  JWT TOOL (offline)\n", "bold"))
    token = ui.ask("JWT")
    if not token:
        return ui.pause()
    try:
        info = jwt_forge.decode(token)
    except Exception as exc:
        print(ui.c(f"Could not decode: {exc}", "red"))
        return ui.pause()
    print("  header :", json.dumps(info["header"]))
    print("  payload:", json.dumps(info["payload"]))
    action = ui.ask("Action: [d]ecode only / [n]one-forge / [c]rack / [s]ign", "d").lower()
    claims = {}
    if action in ("n", "s"):
        raw = ui.ask("Claim overrides as k=v,k=v (blank = none)", "")
        for item in [x for x in raw.split(",") if "=" in x]:
            k, v = item.split("=", 1)
            try:
                claims[k.strip()] = json.loads(v.strip())
            except json.JSONDecodeError:
                claims[k.strip()] = v.strip()
    if action == "n":
        print("\n  " + ui.c("alg:none => " + jwt_forge.forge_none(token, claims), "green"))
    elif action == "c":
        secret = jwt_forge.crack_hs256(token)
        print("\n  secret:", ui.c(secret, "green") if secret else ui.c("(not found)", "yellow"))
    elif action == "s":
        secret = ui.ask("HS256 secret")
        print("\n  " + ui.c(jwt_forge.forge_hs256(token, secret, claims), "green"))
    ui.pause()


def _flow_doctor(ui: UI) -> None:
    import importlib
    import platform
    from ..scanners import all_scanners
    ui.banner()
    print(ui.c("\n  DOCTOR\n", "bold"))
    print(f"  webctf {__version__}  -  python {platform.python_version()} ({sys.platform})")
    print(f"  python >= 3.10: {'yes' if sys.version_info >= (3, 10) else 'NO'}")
    print("\n  Optional dependencies (none required for core):")
    for mod, why in [("rich", "prettier output"), ("playwright", "browser XSS confirmation"),
                     ("flask", "realistic fixtures"), ("jinja2", "realistic SSTI fixtures")]:
        try:
            importlib.import_module(mod)
            print(f"    {ui.c('ok', 'green')}      {mod:11} ({why})")
        except Exception:
            print(f"    {ui.c('--', 'dim')}      {mod:11} ({why})")
    print(f"\n  Registered scanners: {len(all_scanners())}")
    print("  " + ui.c("No AI/LLM runtime. All analysis is deterministic Python.", "dim"))
    ui.pause()


def _flow_plugins(ui: UI) -> None:
    from ..scanners import all_scanners
    ui.banner()
    print(ui.c("\n  SCANNER PLUGINS\n", "bold"))
    for s in sorted(all_scanners(), key=lambda x: x.name):
        exp = ui.c(" [experimental]", "yellow") if s.experimental else ""
        print(f"  {ui.c(s.name, 'cyan'):<20} {s.category}{exp}")
        print(f"      {ui.c(s.description, 'dim')}")
    ui.pause()


_SPINNER = "|/-\\"


def _run_with_progress(ui: UI, url: str, config: RunConfig, source, mode: str) -> Result:
    result = Result(target=url, mode=mode)
    error: dict = {}

    def worker():
        try:
            run_pipeline(url, config, source=source, result=result)
        except Exception as exc:  # surfaced after the thread joins
            error["exc"] = exc

    t = threading.Thread(target=worker, daemon=True)
    print()
    t.start()
    if ui.color:  # animate only on a real terminal
        i = 0
        start = time.monotonic()
        while t.is_alive():
            el = time.monotonic() - start
            spin = _SPINNER[i % len(_SPINNER)]
            line = (f"\r  {spin} working  "
                    f"{result.requests} reqs - {len(result.visited)} locs - "
                    f"{len(result.parameters)} params - {len(result.findings)} findings - "
                    f"{len(result.flags)} flags - {el:4.1f}s   ")
            sys.stdout.write(line[:110])
            sys.stdout.flush()
            time.sleep(0.12)
            i += 1
        sys.stdout.write("\r" + " " * 110 + "\r")
        sys.stdout.flush()
    t.join()
    if "exc" in error:
        raise error["exc"]
    return result


def _render(ui: UI, result: Result) -> None:
    from ..reporting.console import print_summary
    print(ui.c("-" * 62, "cyan"))
    print_summary(result, no_color=not ui.color)
    best = result.best_flag()
    if best and best.verified:
        box = f"  FLAG: {best.value}  "
        print()
        print(ui.c("+" + "-" * (len(box)) + "+", "green"))
        print(ui.c("|" + box + "|", "green"))
        print(ui.c("+" + "-" * (len(box)) + "+", "green"))
    if ui.ask_bool("\nSave report (findings.json + report.md)", False):
        from ..reporting import save_report
        out = ui.ask("Output directory", "./report")
        j, m = save_report(result, out)
        print(ui.c(f"saved: {j}", "dim"))
        print(ui.c(f"saved: {m}", "dim"))
