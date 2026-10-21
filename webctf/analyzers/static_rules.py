"""Conservative line-level static rules for common web-security mistakes.

These are *leads*, not proof. A match means "look here", and the matching line is
quoted so a human can judge reachability. Secrets are never echoed back; their
locations are reported with the value withheld.
"""
from __future__ import annotations

import re

# (regex, title, confidence, explanation, cwe)
RULES: list[tuple[str, str, str, str, str]] = [
    (r"\|\s*safe\b|Markup\s*\(|\bsafe_mode\s*=\s*False",
     "HTML autoescape bypass", "high",
     "Untrusted data rendered without escaping can enable XSS.", "CWE-79"),
    (r"render_template_string\s*\(",
     "Template rendered from a string", "high",
     "User input reaching render_template_string is classic Flask SSTI.", "CWE-1336"),
    (r"(?:innerHTML\s*=|outerHTML\s*=|dangerouslySetInnerHTML|insertAdjacentHTML|document\.write\s*\(|\.html\s*\()",
     "DOM HTML injection sink", "medium",
     "Check whether user-controlled content reaches this browser HTML sink.", "CWE-79"),
    (r"(?<![A-Za-z_])(?:eval|exec|execfile)\s*\(",
     "Dynamic code execution sink", "medium",
     "Check whether attacker-controlled values reach eval/exec.", "CWE-95"),
    (r"\bos\.system\s*\(|\bos\.popen\s*\(|\bsubprocess\.(?:run|Popen|call|check_output)\s*\(|\bcommands\.getoutput\s*\(",
     "OS command execution sink", "medium",
     "Check whether command arguments can be controlled via a request.", "CWE-78"),
    (r"\b(?:shell\s*=\s*True)\b",
     "subprocess shell=True", "medium",
     "shell=True with interpolated input enables command injection.", "CWE-78"),
    (r"\b(?:pickle\.loads|cPickle\.loads|yaml\.unsafe_load|yaml\.load\s*\((?![^)]*Loader)|marshal\.loads|jsonpickle\.decode)\s*\(",
     "Unsafe deserialization sink", "high",
     "Deserializing attacker-controlled data can lead to RCE.", "CWE-502"),
    (r"\b(?:requests\.(?:get|post|put|head)|urllib\.request\.urlopen|httpx\.|aiohttp\.|fetch)\s*\(",
     "Outbound request sink / SSRF lead", "informational",
     "If a URL comes from the request, check server-side URL restrictions.", "CWE-918"),
    (r"(?i)\bdebug\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True",
     "Debug mode enabled", "medium",
     "A reachable debug interface (e.g. Werkzeug console) may expose RCE.", "CWE-489"),
    (r"(?i)[\"']?http_?only[\"']?\s*[=:]\s*(?:False|false|0)\b",
     "JavaScript-readable cookie", "medium",
     "Cookies without HttpOnly can be read by injected JavaScript.", "CWE-1004"),
    (r"(?i)\balgorithms?\s*=\s*\[?\s*[\"']none[\"']|verify\s*=\s*False|verify_signature[\"']?\s*:\s*False",
     "JWT signature not enforced", "high",
     "Accepting alg=none or skipping verification allows token forgery.", "CWE-347"),
    (r"(?i)\b(?:secret_key|jwt_secret|secret|api_key|password|passwd|token)\s*=\s*[\"'][^\"']{3,}",
     "Hardcoded secret", "medium",
     "A secret may be committed in source; inspect locally without posting it.", "CWE-798"),
    (r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\b.{0,60}(?:%s|%\(|\{[^}]*\}|\"\s*\+|'\s*\+|\+\s*(?:request|req|params|input))",
     "SQL built by string formatting", "medium",
     "Interpolated/concatenated SQL with user input risks SQL injection.", "CWE-89"),
    (r"(?i)\.(?:execute|executescript|query|raw)\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\+|\.format))",
     "DB query from formatted string", "high",
     "A database query is built from a format/concat expression.", "CWE-89"),
    (r"(?i)(?:open|file|include|require|send_file|sendfile|readfile|fopen)\s*\([^)]*(?:request|req|params|input|argv)",
     "File path from user input", "medium",
     "A file path derived from input risks path traversal / LFI.", "CWE-22"),
    (r"(?i)(?:request\.(?:args|form|values|json|data|files|cookies|headers)|req\.(?:query|body|params|cookies|headers)|\$_(?:GET|POST|REQUEST|COOKIE)|flask\.request)",
     "User-controlled input source", "informational",
     "Trace this input to HTML, DB, file, URL and command sinks.", "CWE-20"),
    (r"(?i)(?:BLACKLIST|blacklist|allowed_tags|forbidden|denylist|strip_tags|sanitize|clean_html|bleach\.clean)",
     "Custom input filter / sanitizer", "medium",
     "Check parser, attribute filtering, encoded variants and browser behavior.", "CWE-184"),
    (r"(?i)__proto__|constructor\.prototype|Object\.assign\s*\([^,]*,\s*(?:req|request)",
     "Prototype pollution sink", "medium",
     "Merging user input into objects can pollute Object.prototype.", "CWE-1321"),
    (r"JSON\.parse\s*\(\s*`[^`]*\$\{",
     "JSON built from string interpolation", "high",
     "Interpolating input into a JSON string lets an attacker inject arbitrary "
     "keys (e.g. nested __proto__), enabling injection/prototype pollution.", "CWE-74"),
    (r"(?i)<!ENTITY|DOCTYPE[^>\n]*\[|etree\.(?:parse|fromstring|XML)\b|\blxml\b|"
     r"xml\.(?:dom|sax)|parseString\s*\(|resolve_entities\s*=\s*True|XMLParser\s*\(",
     "XML parsing (possible XXE)", "informational",
     "If external entities are enabled on user XML, XXE may be possible.", "CWE-611"),
    (r"(?i)\b(?:flag|secret|answer)\b\s*[:=]\s*[\"'][^\"']+",
     "Potential hardcoded challenge value", "informational",
     "Review this assignment in your local challenge source.", ""),
]

COMPILED = [(re.compile(rx), title, conf, why, cwe) for rx, title, conf, why, cwe in RULES]

# Titles whose matched line must NOT be echoed (may contain a secret/flag).
WITHHELD = {"Hardcoded secret", "Potential hardcoded challenge value"}
