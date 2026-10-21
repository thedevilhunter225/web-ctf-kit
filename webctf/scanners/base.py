"""Scanner interface, shared scan context, and a plugin registry.

Each vulnerability class is an independent :class:`Scanner`. Scanners never talk
to the network directly; they go through :class:`ScanContext`, which enforces the
shared probe budget, records every :class:`~webctf.core.evidence.Attempt`, and
watches every response for flags. This keeps all scanners bounded and auditable,
and makes adding a new one a matter of subclassing and calling :func:`register`.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..core.config import RunConfig
from ..core.evidence import Attempt, Parameter, Result
from ..core.target import Response, Transport
from ..flags.engine import FlagPatterns
from ..flags.watch import record_flags


@dataclass
class Budget:
    """A shared, hard cap on the number of active probe requests."""

    max_tests: int
    performed: int = 0

    def allows(self, n: int = 1) -> bool:
        return self.performed + n <= self.max_tests

    @property
    def remaining(self) -> int:
        return max(0, self.max_tests - self.performed)


def _signal(resp: Response) -> str:
    """A short, stable summary of a response for the attempt log."""
    body = (resp.text or "").strip().replace("\n", " ")
    return f"HTTP {resp.status} len={len(resp.text)} {body[:120]}"


class ScanContext:
    """Everything a scanner needs for one target, with budget + flag watching."""

    def __init__(self, transport: Transport, result: Result, config: RunConfig,
                 budget: Budget, patterns: FlagPatterns):
        self.transport = transport
        self.result = result
        self.config = config
        self.budget = budget
        self.patterns = patterns
        self.run_nonce = secrets.token_hex(5)
        #: targets confirmed by scanners that an exploit module can try under --solve.
        self.solve_targets: list[tuple[str, Parameter, dict]] = []

    def token(self) -> str:
        """A fresh short marker, unique per probe."""
        return secrets.token_hex(4)

    def queue_solve(self, scanner: str, param: Parameter, **hint: object) -> None:
        """Record a confirmed finding for the bounded flag-retrieval phase."""
        self.solve_targets.append((scanner, param, dict(hint)))

    def _inject(self, param: Parameter, payload: str) -> Response:
        values = dict(param.fields)
        values[param.name] = payload
        if param.method == "POST":
            return self.transport.request(param.url, method="POST", data=values)
        parts = urlsplit(param.url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query.update(values)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path,
                          urlencode(query), parts.fragment))
        return self.transport.request(url)

    def fetch(self, path: str, *, category: str, method: str = "GET",
              data: dict[str, str] | None = None,
              json: object | None = None) -> Response | None:
        """Budget-limited raw request for site-scoped scanners and exploits.

        Supports a JSON body via *json* (sets Content-Type: application/json).
        """
        if not self.budget.allows():
            return None
        self.budget.performed += 1
        try:
            resp = self.transport.request(path, method=method, data=data, json=json)
        except (ConnectionError, ValueError) as exc:
            if len(self.result.errors) < 50:
                self.result.errors.append(f"{method} {path}: {exc}")
            return None
        record_flags(self.result, resp.text, path, patterns=self.patterns)
        self.result.add_attempt(Attempt(category=category, target=path, payload="",
                                        expected="", actual=_signal(resp), status=resp.status))
        return resp

    def trial(self, param: Parameter, payload: str, *, category: str,
              expected: str = "") -> tuple[Response | None, Attempt | None]:
        """Send one probe. Returns ``(response, attempt)`` or ``(None, None)``.

        Honours the budget, logs an :class:`Attempt`, and scans the response for
        flags automatically. The caller interprets the response and, on a hit,
        sets ``attempt.supports`` / ``attempt.confidence`` and adds a finding.
        """
        if not self.budget.allows():
            return None, None
        self.budget.performed += 1
        try:
            resp = self._inject(param, payload)
        except (ConnectionError, ValueError) as exc:
            if len(self.result.errors) < 50:
                self.result.errors.append(f"{param.description}: {exc}")
            return None, None
        record_flags(self.result, resp.text, param.description, patterns=self.patterns)
        attempt = Attempt(category=category, target=param.description, payload=payload,
                          expected=expected, actual=_signal(resp), status=resp.status)
        self.result.add_attempt(attempt)
        return resp, attempt


class Scanner:
    """Base class for a vulnerability scanner.

    Subclasses set :attr:`name`, :attr:`category`, and :attr:`experimental`, then
    implement :meth:`scan`. :meth:`applies` is an optional cheap pre-filter.
    """

    name: str = ""
    category: str = ""
    experimental: bool = False
    #: "param" scanners run once per discovered parameter; "site" scanners run
    #: once against the whole target (e.g. path-based disclosure checks).
    scope: str = "param"
    #: human-readable one-liner used by ``webctf plugins``.
    description: str = ""

    def applies(self, param: Parameter, ctx: ScanContext) -> bool:
        return True

    def scan(self, param: Parameter, ctx: ScanContext) -> None:
        """Per-parameter scan. Override for ``scope == 'param'`` scanners."""
        raise NotImplementedError

    def scan_site(self, ctx: ScanContext) -> None:
        """Whole-target scan. Override for ``scope == 'site'`` scanners."""
        raise NotImplementedError


# --- registry --------------------------------------------------------------
_REGISTRY: dict[str, Scanner] = {}


def register(scanner_cls: type[Scanner]) -> type[Scanner]:
    """Class decorator that instantiates and registers a scanner."""
    instance = scanner_cls()
    if not instance.name:
        raise ValueError(f"{scanner_cls.__name__} must set a name")
    _REGISTRY[instance.name] = instance
    return scanner_cls


def all_scanners() -> list[Scanner]:
    return list(_REGISTRY.values())


def get_scanner(name: str) -> Scanner | None:
    return _REGISTRY.get(name)


def scanner_names() -> list[str]:
    return sorted(_REGISTRY)


def select(config: RunConfig) -> list[Scanner]:
    """Return the scanners enabled by *config* (``only`` / ``skip``)."""
    chosen = []
    for scanner in _REGISTRY.values():
        if config.only and scanner.name not in config.only:
            continue
        if scanner.name in config.skip:
            continue
        chosen.append(scanner)
    return chosen
