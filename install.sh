#!/usr/bin/env bash
# Web CTF Kit installer. The core tool needs only Python 3.10+ (standard library);
# this script makes the `webctf` command available and can add optional extras.
set -euo pipefail

cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "[!] python3 not found. Install Python 3.10+ first." >&2
    exit 1
fi

VER=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
echo "[*] Using $PY (Python $VER)"
"$PY" - <<'PYEOF'
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PYEOF
if [ $? -ne 0 ]; then
    echo "[!] Python 3.10+ is required." >&2
    exit 1
fi

MODE="${1:-core}"   # core | rich | dev | all
echo "[*] Install mode: $MODE"

case "$MODE" in
    core) EXTRAS="" ;;
    rich) EXTRAS="[rich]" ;;
    dev)  EXTRAS="[dev]" ;;
    all)  EXTRAS="[all]" ;;
    *) echo "[!] Unknown mode '$MODE' (use: core|rich|dev|all)"; exit 1 ;;
esac

if "$PY" -m pip --version >/dev/null 2>&1; then
    echo "[*] Installing webctf${EXTRAS} (editable)"
    "$PY" -m pip install --upgrade pip >/dev/null 2>&1 || true
    "$PY" -m pip install -e ".${EXTRAS}"
    echo "[+] Installed. Try: webctf --help"
else
    echo "[!] pip is unavailable. You can still run the tool directly:"
    echo "      $PY -m webctf --help"
fi

if [ "$MODE" = "all" ]; then
    echo "[*] Installing Playwright browser (chromium) for XSS confirmation..."
    "$PY" -m playwright install chromium || \
        echo "[!] Playwright browser install failed; browser features are optional."
fi

echo
echo "[+] Quick check:"
"$PY" -m webctf doctor || true
