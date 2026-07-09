"""Registration-time validation of a client-supplied custom PII pattern (F-028).

This is the FIRST line of ReDoS defense (the per-match timeout in engine.py is
the runtime backstop). A pattern that fails ANY check here never reaches the
DB — mirroring the "SSRF guard BEFORE any write" discipline of F-026's
allow-list. Sentinel is itself a security product accepting untrusted regex
from clients; treat every registered pattern as adversarial.
"""

from __future__ import annotations

import re

from data_protection.custom_pii.exceptions import InvalidPattern, InvalidPatternName

# Entity label: uppercase snake, e.g. EMPLOYEE_ID. Surfaced in [REDACTED:{name}].
_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

# Heuristic ReDoS lint: a quantifier applied to a group whose body ALSO ends in
# a quantifier — the classic catastrophic-backtracking shape (a+)+ / (a*)* /
# (a+)* / (.*)+ etc. Matched as "quantifier, group-close(s), quantifier"
# (`[*+][)\]]*[*+]`). This deliberately does NOT flag a group followed by a
# quantifier when the group body is NOT itself quantified — `(abc)*`, `(?:x)?`,
# `(a|b)+` are all safe and common, and an earlier over-broad rule that rejected
# them (`[)\]][*+?]`) produced false positives on legitimate patterns. Not
# exhaustive (e.g. `{n,}`-based nesting slips through); the per-match timeout in
# engine.py is the runtime backstop for whatever the heuristic misses.
_NESTED_QUANTIFIER_RE = re.compile(r"[*+][)\]]*[*+]")


def normalize_name(name: str) -> str:
    """Uppercase-normalize an entity label and validate its shape."""
    normalized = name.strip().upper().replace("-", "_").replace(" ", "_")
    if not _NAME_RE.match(normalized):
        raise InvalidPatternName(
            f"entity name must match ^[A-Z][A-Z0-9_]{{0,63}}$ after normalization, "
            f"got {name!r} -> {normalized!r}"
        )
    return normalized


def validate_pattern(pattern: str, *, max_length: int) -> None:
    """Validate a regex pattern for safe registration.

    Raises InvalidPattern if the pattern is empty, too long, fails to compile,
    or trips the nested-quantifier ReDoS heuristic.
    """
    if not pattern:
        raise InvalidPattern("pattern must not be empty")
    if len(pattern) > max_length:
        raise InvalidPattern(f"pattern exceeds max length {max_length} (got {len(pattern)})")

    # Must compile under the SAME engine used at match time (the `regex` module),
    # so a pattern that stores fine can never fail to load at inspection time.
    try:
        import regex  # noqa: PLC0415 — same engine as engine.py

        regex.compile(pattern)
    except Exception as exc:  # regex.error and anything it wraps
        raise InvalidPattern(f"pattern does not compile: {type(exc).__name__}") from exc

    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise InvalidPattern(
            "pattern rejected by ReDoS heuristic (nested/adjacent quantifiers such "
            "as (a+)+ are a catastrophic-backtracking risk); rewrite it to avoid a "
            "quantifier applied to an already-quantified group"
        )
