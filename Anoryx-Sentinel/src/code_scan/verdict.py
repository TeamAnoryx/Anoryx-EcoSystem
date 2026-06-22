"""Verdict aggregator: findings → PASS | WARN | BLOCK (F-016, ADR-0019 §8).

Aggregates normalised scanner findings against per-tenant severity thresholds
to produce a verdict enum.  The threshold comparison uses a total ordering on
severity levels (low < medium < high < critical).

Fail-safe contract (ADR-0019 §6):
    Any ``ScannerError``, timeout, or other exception passed from the scanner
    layer maps to verdict WARN — never PASS (fail-open) and never BLOCK
    (fail-closed weaponised DoS).  The verdict function itself should never
    raise; callers should wrap it defensively anyway.

Threshold semantics:
    ``thresholds.warn``  — findings at this severity or above → WARN verdict.
    ``thresholds.block`` — findings at this severity or above → BLOCK verdict.
    Both thresholds are compared against the WORST finding severity.
    If no findings exceed ``warn``, verdict is PASS.

Usage::

    from code_scan.verdict import aggregate_verdict, Verdict

    verdict = aggregate_verdict(
        findings=[{"rule_id": "...", "severity": "high", "line": 10}],
        warn_threshold="low",
        block_threshold="high",
    )
    # → Verdict.BLOCK
"""

from __future__ import annotations

from enum import Enum
from typing import Any

# Severity total order: low=0 < medium=1 < high=2 < critical=3.
# "info" is treated the same as "low" for threshold comparison purposes.
_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

_DEFAULT_SEVERITY_RANK: int = 0  # unknown severity → treated as low


class Verdict(str, Enum):
    """Verdict produced by aggregate_verdict."""

    PASS = "PASS"  # noqa: S105 — not a password; this is a verdict label
    WARN = "WARN"
    BLOCK = "BLOCK"


def _rank(severity: str) -> int:
    """Return the integer rank for a severity string (case-insensitive)."""
    return _SEVERITY_ORDER.get(severity.lower(), _DEFAULT_SEVERITY_RANK)


def _top_severity(findings: list[dict[str, Any]]) -> str | None:
    """Return the highest severity string present in *findings*, or None."""
    if not findings:
        return None
    best_rank = -1
    best_sev = "low"
    for f in findings:
        sev = f.get("severity", "low")
        r = _rank(sev)
        if r > best_rank:
            best_rank = r
            best_sev = sev
    return best_sev


def aggregate_verdict(
    findings: list[dict[str, Any]],
    *,
    warn_threshold: str,
    block_threshold: str,
) -> Verdict:
    """Aggregate *findings* against thresholds and return a ``Verdict``.

    Parameters
    ----------
    findings:
        Normalised findings from one or more scanners
        ``[{"rule_id": str, "severity": str, "line": int}]``.
        May be empty (→ ``Verdict.PASS``).
    warn_threshold:
        Minimum severity (inclusive) for a WARN verdict.
        E.g. "low" means any finding at all causes WARN.
    block_threshold:
        Minimum severity (inclusive) for a BLOCK verdict.
        E.g. "high" means findings at high or critical cause BLOCK.
        Must be >= warn_threshold in the severity order; if block_threshold
        ranks below warn_threshold, block is effectively unreachable (callers
        should configure sensibly, but this function is safe regardless).

    Returns
    -------
    Verdict.PASS   — no findings above warn_threshold.
    Verdict.WARN   — at least one finding >= warn_threshold but < block_threshold.
    Verdict.BLOCK  — at least one finding >= block_threshold.
    """
    if not findings:
        return Verdict.PASS

    top_sev = _top_severity(findings)
    if top_sev is None:
        return Verdict.PASS

    top_rank = _rank(top_sev)
    block_rank = _rank(block_threshold)
    warn_rank = _rank(warn_threshold)

    if top_rank >= block_rank:
        return Verdict.BLOCK
    if top_rank >= warn_rank:
        return Verdict.WARN
    return Verdict.PASS


def top_severity_from_findings(findings: list[dict[str, Any]]) -> str:
    """Return the highest severity string in *findings*, or "none" if empty.

    Utility for event payload construction — never raises.
    """
    return _top_severity(findings) or "none"
