"""Bounded dotted-path selector + immutable field withholding (F-017, ADR-0020 §7).

Dialect (Fork 5 — bounded dotted-path, NOT JSONPath):

    a.b.c       — object key descent
    a.b[].c     — descend key ``b`` (a list), then key ``c`` of EVERY element

Every dimension is bounded (R7, threat vector 11): path depth, segment count,
and total nodes visited during a withhold pass.  A path or payload that exceeds a
cap raises (fail-closed): the caller blocks the whole response rather than
risk a partial / unverifiable transform.

Withholding is IMMUTABLE: ``apply_withhold`` returns a NEW structure; the input
object is never mutated (CLAUDE.md coding style).  A matched leaf — whatever its
original type — is replaced with ``WITHHELD_PLACEHOLDER``.  A path that does not
resolve in a given payload is a no-op for that path (the field is simply absent;
nothing to leak), never an error.
"""

from __future__ import annotations

from typing import Any

# Replacement value for a withheld field.  A string marker (not null) so the
# caller can distinguish "withheld by policy" from a genuinely null field.
WITHHELD_PLACEHOLDER = "[withheld:data-lock]"

# Bounds (R7).
MAX_PATH_DEPTH = 16  # max descent segments in a single path
MAX_PATH_SEGMENTS = 16  # max dotted segments (a[].b counts the [] as part of a)
MAX_TRAVERSAL_NODES = 100_000  # max nodes visited across a single apply_withhold pass
MAX_CONTENT_BYTES = 262_144  # 256 KiB cap on the JSON content the detector parses

# Sentinel for an array-wildcard segment ("[]").
ARRAY_WILDCARD = "[]"

# Allowed key characters in a path segment (dotted-path, no wildcards/filters).
_KEY_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


class SelectorError(ValueError):
    """Raised when a path is malformed or exceeds a structural bound (fail-closed)."""


class SelectorBudgetError(SelectorError):
    """Raised when a traversal exceeds MAX_TRAVERSAL_NODES (DoS guard, fail-closed)."""


def parse_path(raw: Any) -> tuple[str, ...]:
    """Parse a dotted path into a tuple of tokens, or raise ``SelectorError``.

    Tokens are key strings, with ``ARRAY_WILDCARD`` inserted after a key written
    as ``key[]``.  Example: ``"a.b[].c"`` → ``("a", "b", "[]", "c")``.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise SelectorError("field_path must be a non-empty string")
    segments = raw.split(".")
    if len(segments) > MAX_PATH_SEGMENTS:
        raise SelectorError(f"field_path exceeds {MAX_PATH_SEGMENTS} segments: {raw!r}")
    tokens: list[str] = []
    for seg in segments:
        if not seg:
            raise SelectorError(f"field_path has an empty segment: {raw!r}")
        is_array = seg.endswith("[]")
        key = seg[:-2] if is_array else seg
        if not key or any(ch not in _KEY_CHARS for ch in key):
            raise SelectorError(f"field_path segment {seg!r} has invalid characters")
        tokens.append(key)
        if is_array:
            tokens.append(ARRAY_WILDCARD)
    if len(tokens) > MAX_PATH_DEPTH:
        raise SelectorError(f"field_path exceeds depth {MAX_PATH_DEPTH}: {raw!r}")
    return tuple(tokens)


class _Budget:
    """Mutable node-visit counter shared across a single apply_withhold pass."""

    __slots__ = ("_remaining",)

    def __init__(self, limit: int) -> None:
        self._remaining = limit

    def tick(self) -> None:
        self._remaining -= 1
        if self._remaining < 0:
            raise SelectorBudgetError(
                f"traversal exceeded {MAX_TRAVERSAL_NODES} nodes — payload too large to lock safely"
            )


def _withhold_one(node: Any, tokens: tuple[str, ...], idx: int, budget: _Budget) -> tuple[Any, int]:
    """Return (new_node, withheld_count) for one path applied at *node*.

    Rebuilds only the structure along the matched path; unmatched branches are
    returned unchanged (no copy needed since nothing is mutated).
    """
    budget.tick()

    if idx >= len(tokens):
        # Reached the target leaf — withhold whatever value is here.
        return WITHHELD_PLACEHOLDER, 1

    token = tokens[idx]

    if token == ARRAY_WILDCARD:
        if not isinstance(node, list):
            return node, 0  # path expects a list here; absent → no-op
        new_items: list[Any] = []
        total = 0
        for item in node:
            new_item, count = _withhold_one(item, tokens, idx + 1, budget)
            new_items.append(new_item)
            total += count
        return new_items, total

    # token is an object key
    if not isinstance(node, dict) or token not in node:
        return node, 0  # path absent → no-op
    new_child, count = _withhold_one(node[token], tokens, idx + 1, budget)
    if count == 0:
        return node, 0  # nothing changed below — return original ref
    new_node = dict(node)
    new_node[token] = new_child
    return new_node, count


def new_budget() -> _Budget:
    """Return a fresh traversal budget that can be SHARED across multiple
    apply_withhold calls so the total node-visit bound holds across all rules in
    one response (not per-rule)."""
    return _Budget(MAX_TRAVERSAL_NODES)


def apply_withhold(
    obj: Any, paths: list[tuple[str, ...]], budget: _Budget | None = None
) -> tuple[Any, int]:
    """Apply every path in *paths* to *obj*, withholding matched leaves.

    Returns ``(new_obj, total_withheld)``.  Immutable: *obj* is not mutated.
    Raises ``SelectorBudgetError`` if traversal exceeds the budget (the caller
    treats this as fail-closed → block the whole response).  Pass a shared
    *budget* (from ``new_budget()``) to bound total work across multiple calls;
    omit it for a fresh per-call budget.
    """
    b = budget if budget is not None else _Budget(MAX_TRAVERSAL_NODES)
    current = obj
    total = 0
    for tokens in paths:
        current, count = _withhold_one(current, tokens, 0, b)
        total += count
    return current, total
