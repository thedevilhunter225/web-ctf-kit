"""Modular vulnerability scanners.

Importing this package registers every built-in scanner. Third-party scanners
can be added by subclassing :class:`~webctf.scanners.base.Scanner` and applying
the :func:`~webctf.scanners.base.register` decorator (see ``docs``/README).
"""
from . import cmdi, crlf, disclosure, lfi, redirect, sqli, ssrf, ssti, xss  # noqa: F401
from .base import (
    Budget, ScanContext, Scanner, all_scanners, get_scanner, register,
    scanner_names, select,
)

__all__ = [
    "Budget", "ScanContext", "Scanner", "all_scanners", "get_scanner",
    "register", "scanner_names", "select",
]
