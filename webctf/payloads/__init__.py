"""Payload sets for scanners and exploit modules.

Payloads are plain data (templates with a ``{m}`` marker or ``{a}``/``{b}``
operands) so they are easy to read, extend and audit. Every payload here is
either an *indicator* probe (harmless markers, arithmetic) or a *read-only*
flag-retrieval command. There are no destructive, write, or denial-of-service
payloads in this toolkit.
"""
