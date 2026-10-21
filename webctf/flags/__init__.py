"""Flag recognition and extraction (regex + nested decoding search)."""
from .engine import (
    DEFAULT_FLAG_REGEX, KNOWN_PREFIX_REGEX, FlagMatch, FlagPatterns,
    compile_pattern, compile_patterns, find_flags, find_flags_deep,
    looks_like_placeholder,
)
from .watch import record_flags

__all__ = [
    "DEFAULT_FLAG_REGEX", "KNOWN_PREFIX_REGEX", "FlagMatch", "FlagPatterns",
    "compile_pattern", "compile_patterns", "find_flags", "find_flags_deep",
    "looks_like_placeholder", "record_flags",
]
