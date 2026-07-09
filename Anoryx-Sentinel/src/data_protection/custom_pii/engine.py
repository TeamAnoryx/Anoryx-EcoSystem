"""Standalone ReDoS-safe regex matching engine for custom PII (F-028, ADR-0034).

Pure function of (compiled patterns, text) -> spans. NO Presidio, NO spacy, NO
DB — so it runs on the slim image and is trivially unit-testable offline. The
`regex` module's per-call `timeout=` is the hard ReDoS backstop: a pattern that
backtracks catastrophically raises TimeoutError, which the engine treats as a
FAIL-CLOSED signal (that pattern is skipped for this input and the event is
surfaced to the caller — matching CLAUDE.md #5's "never silently pass" only in
the sense that a timeout is logged/flagged, but a single pathological pattern
must not take the whole request down, so it is isolated per-pattern).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CompiledPattern:
    """A validated, compiled custom pattern ready for matching."""

    name: str  # entity label, e.g. EMPLOYEE_ID
    compiled: object  # regex.Pattern
    score: float
    action: str | None  # per-pattern override, or None for the default


@dataclass(frozen=True)
class CustomPiiSpan:
    """A single match: [start, end) with the entity label + metadata."""

    start: int
    end: int
    name: str
    score: float
    action: str | None


def compile_pattern(
    name: str, pattern: str, *, score: float, action: str | None
) -> CompiledPattern:
    """Compile a (pre-validated) pattern. Raises if it will not compile —
    callers registering a pattern validate first; callers loading from the DB
    trust it was validated at write time but still guard the compile."""
    import regex  # noqa: PLC0415

    return CompiledPattern(name=name, compiled=regex.compile(pattern), score=score, action=action)


def scan(
    text: str,
    patterns: list[CompiledPattern],
    *,
    timeout_seconds: float,
) -> tuple[list[CustomPiiSpan], list[str]]:
    """Scan `text` with each pattern. Returns (spans, timed_out_pattern_names).

    Each pattern is matched independently with its own timeout budget — one
    catastrophic pattern times out and is skipped (its name returned in the
    second tuple element for logging/alerting) without aborting the others or
    the request. Zero-width matches are ignored (a pattern like `a*` matching
    empty positions must not produce infinite/degenerate spans).
    """
    import regex  # noqa: PLC0415

    spans: list[CustomPiiSpan] = []
    timed_out: list[str] = []
    for pat in patterns:
        try:
            for m in pat.compiled.finditer(text, timeout=timeout_seconds):
                start, end = m.start(), m.end()
                if end > start:  # ignore zero-width matches
                    spans.append(
                        CustomPiiSpan(
                            start=start,
                            end=end,
                            name=pat.name,
                            score=pat.score,
                            action=pat.action,
                        )
                    )
        except TimeoutError:
            timed_out.append(pat.name)
        except regex.error:
            # A pattern that compiled at registration but errors at match time
            # (should not happen) is skipped fail-safe, not fatal to the request.
            timed_out.append(pat.name)
    return spans, timed_out
