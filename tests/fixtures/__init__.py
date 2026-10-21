"""Self-contained, deliberately vulnerable local CTF fixtures (for testing only).

These are tiny WSGI apps that reproduce classic web-CTF bug classes so the solver
can be exercised end to end on localhost. They must never be deployed. Where a
bug would normally need the OS (reading /etc/passwd, running a shell), the fixture
*emulates* that surface safely and deterministically so tests run cross-platform.
"""
