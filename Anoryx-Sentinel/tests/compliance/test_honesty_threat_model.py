"""Honesty threat model tests — vectors 14 and 15 (F-011, ADR-0013 §10).

Vector 14: a control with no Sentinel mapping is always reported as
           not_covered, never silently dropped and never fabricated as passed.
Vector 15: readiness score is recomputable from results; no inflation.

All tests are pure unit tests — NO database dependency.
"""

from __future__ import annotations

import types
from datetime import datetime, timezone

import pytest

from compliance.constants import (
    DISCLAIMER,
    STATUS_NOT_APPLICABLE,
    STATUS_NOT_COVERED,
    STATUS_PASSED,
)
from compliance.evidence import EvidenceProjection
from compliance.gap_analysis import GapAnalysisError, analyze_gaps
from compliance.mapping import ControlEntry, FrameworkMap

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
_T1 = datetime(2026, 1, 31, 23, 59, 59, tzinfo=timezone.utc)


def _projection(
    event_counts: dict[str, int],
    framework: str = "SOC2",
    framework_version: str = "2017-TSC-rev2022",
) -> EvidenceProjection:
    """Build a synthetic EvidenceProjection with no DB dependency."""
    return EvidenceProjection(
        framework=framework,
        framework_version=framework_version,
        t0=_T0,
        t1=_T1,
        event_counts=types.MappingProxyType(event_counts),
        total_events_in_window=sum(event_counts.values()),
        chain_tip=None,
    )


def _entry(
    control_id: str,
    sentinel_controls: tuple[str, ...] = ("sentinel_cap",),
    evidence_event_types: tuple[str, ...] = ("pii_blocked",),
    status_override: str | None = None,
    title: str = "Test control",
    rationale: str | None = None,
) -> ControlEntry:
    return ControlEntry(
        control_id=control_id,
        title=title,
        sentinel_controls=sentinel_controls,
        evidence_event_types=evidence_event_types,
        rationale=rationale,
        status_override=status_override,
    )


def _framework(
    controls: list[ControlEntry],
    framework: str = "SOC2",
    framework_version: str = "2017-TSC-rev2022",
) -> FrameworkMap:
    return FrameworkMap(
        framework=framework,
        framework_version=framework_version,
        controls=tuple(controls),
    )


# ---------------------------------------------------------------------------
# Vector 14 — fabricated coverage guard (R8)
# ---------------------------------------------------------------------------


class TestUncoveredControlReportedAsGap:
    """Vector 14: a control with sentinel_controls=() must surface as
    STATUS_NOT_COVERED; it must NOT be counted as passed and must NOT be
    silently dropped from results.
    """

    def test_uncovered_control_reported_as_not_covered(self) -> None:
        # Arrange
        uncovered = _entry("CC9.9", sentinel_controls=(), evidence_event_types=())
        fm = _framework([uncovered])
        proj = _projection({})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert — present in results, correct status
        assert len(report.results) == 1
        result = report.results[0]
        assert result.control_id == "CC9.9"
        assert result.status == STATUS_NOT_COVERED

    def test_uncovered_control_is_not_counted_as_passed(self) -> None:
        # Arrange — mix of uncovered + one genuinely passing control
        uncovered = _entry("CC9.9", sentinel_controls=(), evidence_event_types=())
        covered = _entry("CC7.2", evidence_event_types=("pii_blocked",))
        fm = _framework([uncovered, covered])
        proj = _projection({"pii_blocked": 5})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert — exactly 1 passed (CC7.2), not 2
        assert report.passed == 1
        assert report.not_covered == 1

    def test_uncovered_control_is_not_silently_dropped(self) -> None:
        # Arrange — three controls: one uncovered, two with evidence
        c1 = _entry("CC7.1", evidence_event_types=("pii_blocked",))
        c2 = _entry("CC9.9", sentinel_controls=(), evidence_event_types=())
        c3 = _entry("CC7.2", evidence_event_types=("policy_decision_allow",))
        fm = _framework([c1, c2, c3])
        proj = _projection({"pii_blocked": 3, "policy_decision_allow": 1})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert — total = 3, all three appear in results
        assert report.total == 3
        ids = {r.control_id for r in report.results}
        assert "CC9.9" in ids

    def test_uncovered_control_evidence_count_is_zero(self) -> None:
        # Arrange — even if the projection has counts, uncovered count = 0
        uncovered = _entry("CC9.9", sentinel_controls=(), evidence_event_types=())
        fm = _framework([uncovered])
        proj = _projection({"pii_blocked": 99})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert
        assert report.results[0].evidence_count == 0

    def test_uncovered_control_counted_in_not_covered_aggregate(self) -> None:
        # Arrange
        c1 = _entry("CC1", sentinel_controls=(), evidence_event_types=())
        c2 = _entry("CC2", sentinel_controls=(), evidence_event_types=())
        fm = _framework([c1, c2])
        proj = _projection({})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert
        assert report.not_covered == 2
        assert report.passed == 0
        assert report.gap == 0


# ---------------------------------------------------------------------------
# Vector 15 — readiness score recomputable from results (no inflation)
# ---------------------------------------------------------------------------


class TestReadinessScoreMatchesEvidence:
    """Vector 15: readiness must be recomputable independently from results;
    no weighting, no inflation allowed.
    """

    def test_readiness_recomputable_from_results_mixed_set(self) -> None:
        # Arrange — passed=2, gap=1, not_covered=1, not_applicable=1 -> total=5
        c_passed_1 = _entry("CC1", evidence_event_types=("pii_blocked",))
        c_passed_2 = _entry("CC2", evidence_event_types=("policy_decision_allow",))
        c_gap = _entry("CC3", evidence_event_types=("injection_detected",))
        c_not_covered = _entry("CC4", sentinel_controls=(), evidence_event_types=())
        c_na = _entry("CC5", status_override="not_applicable")
        fm = _framework([c_passed_1, c_passed_2, c_gap, c_not_covered, c_na])
        proj = _projection({"pii_blocked": 10, "policy_decision_allow": 3})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert counts
        assert report.passed == 2
        assert report.gap == 1
        assert report.not_covered == 1
        assert report.not_applicable == 1
        assert report.total == 5
        assert report.applicable == 4  # total - not_applicable

        # Independently recompute readiness from results
        passed_count = sum(1 for r in report.results if r.status == STATUS_PASSED)
        na_count = sum(1 for r in report.results if r.status == STATUS_NOT_APPLICABLE)
        applicable_count = len(report.results) - na_count
        expected_readiness = passed_count / applicable_count

        assert report.readiness == pytest.approx(expected_readiness)

    def test_readiness_no_inflation_not_covered_excluded_from_numerator(self) -> None:
        # Arrange — only not_covered controls: readiness must be 0.0, NOT 1.0
        controls = [
            _entry(f"CC{i}", sentinel_controls=(), evidence_event_types=()) for i in range(3)
        ]
        fm = _framework(controls)
        proj = _projection({})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert — not_covered does NOT inflate the score
        assert report.readiness == 0.0
        assert report.passed == 0

    def test_readiness_all_passed_is_one(self) -> None:
        # Arrange — every control has evidence
        c1 = _entry("CC1", evidence_event_types=("pii_blocked",))
        c2 = _entry("CC2", evidence_event_types=("policy_decision_allow",))
        fm = _framework([c1, c2])
        proj = _projection({"pii_blocked": 5, "policy_decision_allow": 2})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert
        assert report.readiness == pytest.approx(1.0)
        assert report.passed == 2
        assert report.applicable == 2

    def test_readiness_independently_derivable_all_gap(self) -> None:
        # Arrange — all mapped, none have evidence
        c1 = _entry("CC1", evidence_event_types=("pii_blocked",))
        c2 = _entry("CC2", evidence_event_types=("injection_detected",))
        fm = _framework([c1, c2])
        proj = _projection({})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert — both gap, readiness = 0/2 = 0.0
        assert report.readiness == pytest.approx(0.0)
        assert report.gap == 2
        assert report.passed == 0

        # Recompute
        passed_r = sum(1 for r in report.results if r.status == STATUS_PASSED)
        na_r = sum(1 for r in report.results if r.status == STATUS_NOT_APPLICABLE)
        applicable_r = len(report.results) - na_r
        assert report.readiness == pytest.approx(passed_r / applicable_r)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestReadinessEdgeCases:
    def test_applicable_zero_returns_readiness_zero_not_division_error(self) -> None:
        # Arrange — all controls are not_applicable
        c1 = _entry("CC1", status_override="not_applicable")
        c2 = _entry("CC2", status_override="not_applicable")
        fm = _framework([c1, c2])
        proj = _projection({})

        # Act — must not raise ZeroDivisionError
        report = analyze_gaps(fm, proj)

        # Assert — 0.0, never 1.0
        assert report.readiness == 0.0
        assert report.applicable == 0
        assert report.not_applicable == 2

    def test_applicable_zero_empty_controls(self) -> None:
        # Arrange — no controls at all
        fm = _framework([])
        proj = _projection({})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert
        assert report.readiness == 0.0
        assert report.total == 0
        assert report.applicable == 0

    def test_not_applicable_excluded_from_denominator(self) -> None:
        # Arrange — 2 passed, 1 not_applicable -> applicable = 2
        c_p1 = _entry("CC1", evidence_event_types=("pii_blocked",))
        c_p2 = _entry("CC2", evidence_event_types=("policy_decision_allow",))
        c_na = _entry("CC3", status_override="not_applicable")
        fm = _framework([c_p1, c_p2, c_na])
        proj = _projection({"pii_blocked": 1, "policy_decision_allow": 1})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert denominator is 2 not 3
        assert report.applicable == 2
        assert report.not_applicable == 1
        assert report.readiness == pytest.approx(1.0)

    def test_evidence_count_sums_multiple_event_types(self) -> None:
        # Arrange — one control with 2 mapped event types
        c = _entry(
            "CC7.2",
            evidence_event_types=("pii_blocked", "injection_detected"),
        )
        fm = _framework([c])
        proj = _projection({"pii_blocked": 7, "injection_detected": 3})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert — count = 7 + 3 = 10
        assert report.results[0].evidence_count == 10
        assert report.results[0].status == STATUS_PASSED

    def test_evidence_count_partial_event_types(self) -> None:
        # Arrange — control has 2 types but projection only has one
        c = _entry(
            "CC7.2",
            evidence_event_types=("pii_blocked", "injection_detected"),
        )
        fm = _framework([c])
        proj = _projection({"pii_blocked": 4})

        # Act
        report = analyze_gaps(fm, proj)

        # Assert — count = 4 (injection_detected is 0 / absent)
        assert report.results[0].evidence_count == 4
        assert report.results[0].status == STATUS_PASSED


class TestFrameworkMismatch:
    def test_framework_name_mismatch_raises_gap_analysis_error(self) -> None:
        # Arrange
        fm = _framework([], framework="SOC2")
        proj = _projection({}, framework="ISO27001")

        # Act / Assert
        with pytest.raises(GapAnalysisError, match="Framework mismatch"):
            analyze_gaps(fm, proj)

    def test_framework_version_mismatch_raises_gap_analysis_error(self) -> None:
        # Arrange
        fm = _framework([], framework_version="2017-TSC-rev2022")
        proj = _projection({}, framework_version="2017-TSC-rev2023")

        # Act / Assert
        with pytest.raises(GapAnalysisError, match="version mismatch"):
            analyze_gaps(fm, proj)

    def test_matching_framework_and_version_does_not_raise(self) -> None:
        # Arrange
        fm = _framework([])
        proj = _projection({})

        # Act / Assert — must not raise
        report = analyze_gaps(fm, proj)
        assert report.framework == "SOC2"


class TestGapReportInvariants:
    def test_disclaimer_always_equals_constant(self) -> None:
        fm = _framework([])
        proj = _projection({})
        report = analyze_gaps(fm, proj)
        assert report.disclaimer == DISCLAIMER

    def test_disclaimer_contains_auditor_phrase(self) -> None:
        fm = _framework([])
        proj = _projection({})
        report = analyze_gaps(fm, proj)
        assert "Certification requires an accredited auditor." in report.disclaimer

    def test_total_equals_sum_of_status_counts(self) -> None:
        c1 = _entry("CC1", evidence_event_types=("pii_blocked",))
        c2 = _entry("CC2", evidence_event_types=("injection_detected",))
        c3 = _entry("CC3", sentinel_controls=(), evidence_event_types=())
        c4 = _entry("CC4", status_override="not_applicable")
        fm = _framework([c1, c2, c3, c4])
        proj = _projection({"pii_blocked": 1})

        report = analyze_gaps(fm, proj)

        # total is the sum of all four status buckets
        assert report.total == (
            report.passed + report.gap + report.not_covered + report.not_applicable
        )

    def test_applicable_equals_total_minus_not_applicable(self) -> None:
        c1 = _entry("CC1", evidence_event_types=("pii_blocked",))
        c2 = _entry("CC2", status_override="not_applicable")
        fm = _framework([c1, c2])
        proj = _projection({"pii_blocked": 1})

        report = analyze_gaps(fm, proj)

        assert report.applicable == report.total - report.not_applicable

    def test_window_timestamps_propagated_from_projection(self) -> None:
        fm = _framework([])
        proj = _projection({})
        report = analyze_gaps(fm, proj)
        assert report.t0 == _T0
        assert report.t1 == _T1

    def test_report_is_frozen_immutable(self) -> None:
        from dataclasses import FrozenInstanceError

        fm = _framework([])
        proj = _projection({})
        report = analyze_gaps(fm, proj)
        with pytest.raises(FrozenInstanceError):
            report.readiness = 9.9  # type: ignore[misc]

    def test_control_result_is_frozen_immutable(self) -> None:
        from dataclasses import FrozenInstanceError

        c = _entry("CC1", evidence_event_types=("pii_blocked",))
        fm = _framework([c])
        proj = _projection({"pii_blocked": 1})
        report = analyze_gaps(fm, proj)
        with pytest.raises(FrozenInstanceError):
            report.results[0].status = "mutated"  # type: ignore[misc]

    def test_inputs_not_mutated(self) -> None:
        # Arrange — record original state
        c = _entry("CC1", evidence_event_types=("pii_blocked",))
        fm = _framework([c])
        original_controls = fm.controls
        proj = _projection({"pii_blocked": 5})
        original_counts = dict(proj.event_counts)

        # Act
        analyze_gaps(fm, proj)

        # Assert — inputs unchanged
        assert fm.controls == original_controls
        assert dict(proj.event_counts) == original_counts


class TestStatusOverrideNotApplicable:
    def test_not_applicable_overrides_regardless_of_evidence(self) -> None:
        # Even if there is evidence for the event types, the override wins
        c = _entry(
            "CC9.9",
            sentinel_controls=("some_cap",),
            evidence_event_types=("pii_blocked",),
            status_override="not_applicable",
        )
        fm = _framework([c])
        proj = _projection({"pii_blocked": 100})

        report = analyze_gaps(fm, proj)

        assert report.results[0].status == STATUS_NOT_APPLICABLE
        assert report.results[0].evidence_count == 0

    def test_not_applicable_not_counted_in_applicable(self) -> None:
        c_na = _entry("CC1", status_override="not_applicable")
        c_gap = _entry("CC2", evidence_event_types=("pii_blocked",))
        fm = _framework([c_na, c_gap])
        proj = _projection({})

        report = analyze_gaps(fm, proj)

        assert report.applicable == 1  # only CC2
        assert report.not_applicable == 1
        assert report.readiness == pytest.approx(0.0)  # 0 passed / 1 applicable
