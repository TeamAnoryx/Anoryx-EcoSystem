"""Compliance gap analysis + readiness scoring (F-011, ADR-0013 §5 D4).

Consumes an immutable FrameworkMap and an EvidenceProjection, applies the
four-status logic defined in D4, and returns an immutable GapReport.

Honest-language rule: "audit-ready" throughout; never "compliant".
Mandatory disclaimer: "Certification requires an accredited auditor."

R8 (cardinal): NEVER fabricate coverage.  A control with no Sentinel mapping
is ALWAYS reported as not_covered, never as passed or gap.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from compliance.constants import (
    DISCLAIMER,
    STATUS_GAP,
    STATUS_NOT_APPLICABLE,
    STATUS_NOT_COVERED,
    STATUS_PASSED,
)
from compliance.errors import GapAnalysisError
from compliance.evidence import EvidenceProjection
from compliance.mapping import ControlEntry, FrameworkMap

# ---------------------------------------------------------------------------
# Immutable result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ControlResult:
    """Immutable status for a single framework control after gap analysis.

    Fields
    ------
    control_id:
        Framework-specific identifier (e.g. "CC7.2").
    title:
        Human-readable control title.
    status:
        One of STATUS_PASSED / STATUS_GAP / STATUS_NOT_APPLICABLE /
        STATUS_NOT_COVERED.
    evidence_event_types:
        Tuple of event types that were checked for this control.
    evidence_count:
        Sum of projection.event_counts values for this control's
        evidence_event_types within the evidence window.  Zero when
        not_applicable or not_covered.
    rationale:
        Optional explanation from the YAML mapping.
    """

    control_id: str
    title: str
    status: str
    evidence_event_types: tuple[str, ...]
    evidence_count: int
    rationale: str | None


@dataclass(frozen=True)
class GapReport:
    """Immutable gap analysis report for a framework over an evidence window.

    Readiness formula (D4, no weighting, no inflation):
        readiness = passed / applicable
        applicable = total - not_applicable
        Edge: applicable == 0 -> readiness = 0.0 (never ZeroDivisionError,
        never inflated to 1.0).

    The score is fully recomputable from results (vector 15).
    The disclaimer is mandatory on every artifact (ADR-0013 §5).
    """

    framework: str
    framework_version: str
    t0: datetime
    t1: datetime
    results: tuple[ControlResult, ...]
    total: int
    passed: int
    gap: int
    not_applicable: int
    not_covered: int
    applicable: int
    readiness: float
    disclaimer: str


# ---------------------------------------------------------------------------
# Internal helpers (each < 50 lines)
# ---------------------------------------------------------------------------


def _check_framework_consistency(
    framework_map: FrameworkMap,
    projection: EvidenceProjection,
) -> None:
    """Raise GapAnalysisError if framework or framework_version do not match.

    Fail-closed: a mismatch means the evidence was generated for a different
    framework or framework revision.  Silently mixing them would produce an
    incorrect report (R8).
    """
    if framework_map.framework != projection.framework:
        raise GapAnalysisError(
            f"Framework mismatch: FrameworkMap declares '{framework_map.framework}' "
            f"but EvidenceProjection is for '{projection.framework}'.  "
            f"Generate evidence and run gap analysis with the same framework."
        )
    if framework_map.framework_version != projection.framework_version:
        raise GapAnalysisError(
            f"Framework version mismatch for '{framework_map.framework}': "
            f"FrameworkMap version '{framework_map.framework_version}' does not match "
            f"EvidenceProjection version '{projection.framework_version}'.  "
            f"Fail-closed: regenerate evidence against the current mapping version."
        )


def _sum_evidence(
    entry: ControlEntry,
    event_counts: dict[str, int],
) -> int:
    """Return the total evidence count for a single control.

    Sums event_counts values for each of the control's evidence_event_types.
    Missing keys are treated as zero (evidence absent, not an error).
    """
    return sum(event_counts.get(et, 0) for et in entry.evidence_event_types)


def _classify_control(
    entry: ControlEntry,
    evidence_count: int,
) -> str:
    """Apply the D4 passed/gap distinction for a single mapped control.

    Called only when status_override and empty sentinel_controls have already
    been handled by _build_control_result — those branches are not repeated here.

    Priority order (ADR-0013 §5):
    1. evidence_count >= 1  -> STATUS_PASSED
    2. otherwise            -> STATUS_GAP
    """
    if evidence_count >= 1:
        return STATUS_PASSED
    return STATUS_GAP


def _build_control_result(
    entry: ControlEntry,
    event_counts: dict[str, int],
) -> ControlResult:
    """Build an immutable ControlResult for one ControlEntry."""
    # not_applicable forces evidence_count to 0 (R8: honest, no phantom count).
    if entry.status_override == STATUS_NOT_APPLICABLE:
        return ControlResult(
            control_id=entry.control_id,
            title=entry.title,
            status=STATUS_NOT_APPLICABLE,
            evidence_event_types=entry.evidence_event_types,
            evidence_count=0,
            rationale=entry.rationale,
        )
    # not_covered: no Sentinel mapping, no evidence (R8).
    if not entry.sentinel_controls:
        return ControlResult(
            control_id=entry.control_id,
            title=entry.title,
            status=STATUS_NOT_COVERED,
            evidence_event_types=entry.evidence_event_types,
            evidence_count=0,
            rationale=entry.rationale,
        )
    # _classify_control assumes status_override and empty sentinel_controls were filtered above.
    count = _sum_evidence(entry, event_counts)
    status = _classify_control(entry, count)
    return ControlResult(
        control_id=entry.control_id,
        title=entry.title,
        status=status,
        evidence_event_types=entry.evidence_event_types,
        evidence_count=count,
        rationale=entry.rationale,
    )


def _compute_aggregates(
    results: tuple[ControlResult, ...],
) -> tuple[int, int, int, int, int, float]:
    """Derive (total, passed, gap, not_applicable, not_covered, applicable, readiness).

    Returns a 6-tuple: (passed, gap, not_applicable, not_covered, applicable, readiness).
    Total is len(results); caller combines.

    readiness = passed / applicable.
    applicable = total - not_applicable.
    Edge: applicable == 0 -> readiness = 0.0 (never ZeroDivisionError, never 1.0).
    """
    passed = sum(1 for r in results if r.status == STATUS_PASSED)
    gap = sum(1 for r in results if r.status == STATUS_GAP)
    not_applicable = sum(1 for r in results if r.status == STATUS_NOT_APPLICABLE)
    not_covered = sum(1 for r in results if r.status == STATUS_NOT_COVERED)
    applicable = len(results) - not_applicable
    readiness = passed / applicable if applicable > 0 else 0.0
    return passed, gap, not_applicable, not_covered, applicable, readiness


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_gaps(
    framework_map: FrameworkMap,
    projection: EvidenceProjection,
) -> GapReport:
    """Analyze control gaps and compute an audit-ready readiness score.

    Applies the D4 four-status classification to every control in
    *framework_map* using evidence counts from *projection*.  Returns an
    immutable GapReport.  Inputs are never mutated.

    Parameters
    ----------
    framework_map:
        Loaded and validated FrameworkMap (from compliance.mapping.load_framework).
    projection:
        Immutable EvidenceProjection for the same framework and version.

    Returns
    -------
    GapReport
        Immutable.  readiness = passed / applicable; 0.0 when applicable == 0.
        disclaimer is always set to the DISCLAIMER constant.

    Raises
    ------
    GapAnalysisError
        If framework or framework_version differ between the two inputs
        (fail-closed; never silently produces a mixed report).
    """
    _check_framework_consistency(framework_map, projection)

    # Materialise event_counts as a plain dict for O(1) lookups.
    event_counts: dict[str, int] = dict(projection.event_counts)

    results: tuple[ControlResult, ...] = tuple(
        _build_control_result(entry, event_counts) for entry in framework_map.controls
    )

    passed, gap, not_applicable, not_covered, applicable, readiness = _compute_aggregates(results)

    return GapReport(
        framework=framework_map.framework,
        framework_version=framework_map.framework_version,
        t0=projection.t0,
        t1=projection.t1,
        results=results,
        total=len(results),
        passed=passed,
        gap=gap,
        not_applicable=not_applicable,
        not_covered=not_covered,
        applicable=applicable,
        readiness=readiness,
        disclaimer=DISCLAIMER,
    )
