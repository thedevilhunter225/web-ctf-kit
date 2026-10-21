# Web CTF Kit

**Deterministic, no-AI autonomous Web CTF toolkit.** Fingerprint a challenge,
analyze its source, discover inputs, test the high-value web bug classes, chain
source→dynamic→exploit signals, and *read out the flag* — all with conventional
Python, deterministic algorithms, vulnerability signatures, AST taint analysis and
established standard-library tooling. **No LLM, no cloud inference, no AI API** at
run time, so it is usable at on-site competitions where AI assistants are banned.

```text
WEB CTF SOLVER  --  deterministic, no-AI toolkit for authorized CTFs
[+] Target: http://127.0.0.1:8000/
[+] Mode: solve  |  Stack: Flask/Werkzeug
[+] Source analyzed: 10 files, frameworks: Flask/Werkzeug
[+] Discovered: 6 locations, 3 input parameters
[+] Active probes sent: 58 (62 total requests)
[+] Findings: 4 (1 confirmed, 2 high/observed)
[+] Server-side template injection (high)   GET / ?name=
[+] Flag retrieved via SSTI (confirmed)     GET / ?name=
[+] FLAG: flag{deterministic_solve}   (verified via ssti)
```

## Why this design

- **Zero required dependencies.** The `webctf` core imports only the Python
  standard library, so it runs on a stock Kali / Python 3.10+ box with no install
  friction and no network. Rich, Playwright, Flask, PyYAML are *optional* extras
  that are auto-detected and degrade gracefully.
- **Deterministic & auditable.** Every active probe is recorded as a reproducible
  `Attempt`; every finding has an explicit confidence. A result is only
  `confirmed` when backed by a real artifact (template arithmetic that evaluated,
  a flag read out through the bug, a DB value extracted).
- **Scoped & bounded by default.** Same-origin only (redirects off-origin are
  refused, never followed), hard request/probe budgets, rate limiting, overall
  time budget, passive by default. Active probing and flag retrieval are opt-in.

## Install

Fastest (no install — just the standard library):

```bash
python3 -m webctf --help
```

Or install the `webctf` command:

```bash
./install.sh            # core (zero deps)
./install.sh rich       # + colored output
./install.sh dev        # + flask/jinja2/pyyaml for realistic fixtures & tests
./install.sh all        # + playwright (browser XSS confirmation)
# equivalently:  python3 -m pip install -e ".[all]"
```

Requirements: **Python 3.11+ recommended (3.10 supported)**. Runs on Kali Linux,
macOS and Windows.

## One-command solve

```bash
# Black-box:
webctf solve --url http://CHALLENGE-IP:PORT/ --ack-authorized

# White-box (recommended when source is provided — enables source→sink planning):
webctf solve --url http://CHALLENGE-IP:PORT/ --source dist.zip --ack-authorized
```

`solve` runs the full pipeline: fingerprint → (optional) source analysis →
same-origin crawl & input discovery → deterministic planner → modular scanners →
bounded, read-only flag retrieval → report. `--ack-authorized` is required because
`solve`/`scan` send active probes.

## Commands

| Command | Purpose | Network |
|---|---|---|
| `webctf solve --url URL [--source ZIP]` | Full autonomous pipeline + flag retrieval | challenge only |
| `webctf recon --url URL` | Passive crawl + fingerprint + flag spotting (no payloads) | challenge only |
| `webctf scan --url URL --ack-authorized` | Active vulnerability probes (no auto-solve) | challenge only |
| `webctf analyze --source ZIP` (alias `source`) | Offline source analysis (ZIP/TAR/dir/file) | none |
| `webctf report --input findings.json` | Pretty-print a saved report | none |
| `webctf doctor` | Environment / optional-dependency check | none |
| `webctf plugins` | List scanner plugins | none |
| `webctf bot --url URL ... --ack-authorized` | Submit one URL to an admin `/report` endpoint | challenge only |
| `webctf bot --url URL --capture ... --ack-authorized` | Auto cookie-exfil: local listener + XSS via `/report` → prints the flag | challenge only |
| `webctf jwt TOKEN [--forge-none\|--crack\|--secret S]` | Decode / forge / crack a JWT (offline) | none |

Common flags: `--max-pages`, `--max-tests`, `--max-time`, `--timeout`, `--delay`,
`--cookie`, `--header NAME:VALUE`, `--guess`, `--only a,b` / `--skip a,b`,
`--flag-regex`, `--flag-only`, `--output DIR`, `--json`, `--no-color`, `--verbose`.

### Custom flag format

```bash
webctf solve --url http://host/ --ack-authorized --flag-regex 'PCC\{[^}]+\}'
```

The flag engine also peels **Base64 / Base64url / hex / URL / ROT13** layers to
find encoded flags, and filters obvious placeholders (`flag{...}`, `flag{FLAG}`).

## Supported techniques

**Confirmed-with-flag-retrieval (tested end-to-end against local fixtures):**

- Server-side template injection (SSTI) — arithmetic detection across engine
  families; read-only flag retrieval via Jinja2 `cycler`/`lipsum` gadgets and a
  generic Python fallback (validated against *real* Jinja2 and a stdlib evaluator).
- SQL injection — error-based, boolean-based (blind), and time-based detection;
  UNION-based extraction (ORDER BY column discovery → reflected-column → read-only
  scalar sub-queries).
- Local file inclusion / path traversal — `/etc/passwd` confirmation; read-only
  flag-path reads and `php://filter` source disclosure.
- OS command injection — `echo`-marker detection through shell separators;
  read-only `cat` flag retrieval.

**Detection (high-signal, no automatic exploitation):**

- Reflected XSS, including tag/attribute **blacklist-bypass** probing.
- Open redirect, CRLF / HTTP response-header injection.
- Source / backup / `.git` / `.env` / DB-dump / archive disclosure.
- Prototype-pollution gadgets and JSON-from-interpolation (white-box; see below).
- JWT `alg:none` / weak-secret (offline forge & crack via `webctf jwt`).

**Experimental / partial:** SSRF (scope-safe reflection heuristic; no external
callbacks by default). **Not auto-exploited:** DOM-only/SPA XSS, admin-bot cookie
exfiltration (the `bot` helper submits URLs but a browser confirms execution),
race conditions, deserialization gadget chains, XXE payloads, multi-step business
logic. These are surfaced as *leads*; the tool never fabricates success.

### White-box source analysis

`analyze` / `--source` performs, entirely offline:

- Framework & route identification (Flask/Django/FastAPI/Express/Laravel/Rails/…).
- **Python AST taint analysis** — tracks request sources (`request.args/form/…`)
  through variable assignments and string-building into dangerous sinks
  (`render_template_string`, `eval`/`exec`, `os.system`/`subprocess`,
  `cursor.execute`, `open`/`send_file`, deserializers) with far fewer false
  positives than a line regex.
- JS sink detection incl. **unsafe recursive `merge` (prototype pollution)** and
  `JSON.parse` built from string interpolation.
- Dockerfile / docker-compose secrets & ports (values withheld), config discovery.

Source findings **drive the planner**: a confirmed SSTI sink in the source raises
SSTI probe priority and points it at the right input, so the live scan tests the
most likely bug first and spends its budget where the evidence points.

## Safety & scope

- Test **only** CTF instances, local labs, or targets you are explicitly
  authorized to assess. Active probing requires `--ack-authorized`.
- Same-origin scope is enforced in the transport layer: off-origin redirects are
  refused, `Host`/`Content-Length`/`Transfer-Encoding` cannot be overridden, and
  CR/LF in outgoing headers is rejected.
- All exploitation is **read-only** flag retrieval (env var, `cat`, file read,
  `SELECT`). There are no destructive, write, brute-force, DoS, mass-targeting or
  external-exfiltration features, and no out-of-band callbacks by default.
- Budgets: `--max-pages`, `--max-tests`, `--max-time`, `--timeout`, `--delay`,
  512 KiB response cap, 800 source files / 48 MiB archive caps.

## Architecture / plugins

```text
webctf/
├── cli.py                 # argparse CLI (solve/recon/scan/analyze/report/doctor/plugins/bot/jwt)
├── core/                  # config, target (scoped transport), evidence, planner, engine
├── recon/                 # fingerprint, crawler, HTML parser, path discovery
├── analyzers/             # archive, static rules, python AST taint, JS analysis, docker, scan
├── scanners/              # base + registry; xss, sqli, ssti, lfi, cmdi, redirect, crlf, ssrf, disclosure
├── exploits/              # ssti_rce, lfi_read, sqli_extract, cmdi_read, jwt_forge (+ run_solve)
├── payloads/              # xss, ssti, lfi, sqli, cmdi payload sets (data)
├── flags/                 # recognition + nested-decoding engine
├── browser/              # admin-bot report workflow + optional Playwright driver
└── reporting/             # console (rich-or-plain), markdown, json
```

Add a scanner in a few lines — subclass `Scanner`, call `@register`:

```python
from webctf.scanners.base import Scanner, ScanContext, register
from webctf.core.evidence import Finding

@register
class MyScanner(Scanner):
    name = "mything"
    category = "My vulnerability"
    description = "What it checks."

    def scan(self, param, ctx: ScanContext) -> None:
        resp, attempt = ctx.trial(param, "payload", category=self.category)
        if resp and "signal" in resp.text:
            ctx.result.add_finding(Finding(
                self.category, "high", param.description, "evidence",
                "why", "next step", origin="dynamic"))
            ctx.queue_solve("mything", param)   # optional: hand to an exploit module
```

It is then picked up by `webctf plugins`, the planner and `solve`.

## Tests & fixtures

Self-contained, deliberately vulnerable fixtures under `tests/fixtures/` (served
on `127.0.0.1` only) let the solver be exercised end to end:

```bash
python3 -m unittest discover -s tests -v
```

The suite covers XSS (blacklist bypass), SSTI (stdlib + real Jinja2), SQLi (UNION
extraction), LFI, command injection, open redirect, CRLF, blind boolean SQLi,
disclosure, source AST taint, prototype-pollution detection, the flag engine, the
CLI, and the admin-bot workflow — asserting *actual flag extraction*, not just
alerts.

## No AI

No calls to OpenAI, Anthropic, Google, Hugging Face or any model/inference service
at run time; no network except to the authorized target. This repository's code
was authored with AI assistance *before* an event, but the tool has **no AI
runtime**. Some competitions also restrict pre-prepared or externally-authored
tooling — confirm your event's rules before use.

MIT licensed. Contributions and new checks welcome.
