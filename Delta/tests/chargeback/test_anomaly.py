"""Pure trailing-average anomaly detection: no I/O, no DB (D-012, ADR-0012 §2 fork 1)."""

from __future__ import annotations

import pytest

from delta.chargeback.anomaly import (
    DEFAULT_MIN_FLOOR_CENTS,
    DEFAULT_SPIKE_RATIO_THRESHOLD,
    detect_anomalies,
)


def test_baseline_periods_below_one_raises():
    with pytest.raises(ValueError, match="baseline_periods must be >= 1"):
        detect_anomalies(
            current_by_group={"a": 10_000},
            baseline_total_by_group={"a": 1_000},
            baseline_periods=0,
        )


def test_flat_spend_is_not_flagged():
    results = detect_anomalies(
        current_by_group={"team-a": 5_000},
        baseline_total_by_group={"team-a": 5_000 * 7},  # avg == current
        baseline_periods=7,
    )
    assert results == []


def test_spike_at_exactly_threshold_is_flagged():
    baseline_avg = 1_000
    results = detect_anomalies(
        current_by_group={"team-a": int(baseline_avg * DEFAULT_SPIKE_RATIO_THRESHOLD)},
        baseline_total_by_group={"team-a": baseline_avg * 7},
        baseline_periods=7,
    )
    assert len(results) == 1
    assert results[0].code == "SPEND_SPIKE"
    assert results[0].severity == "warning"
    assert results[0].ratio == pytest.approx(DEFAULT_SPIKE_RATIO_THRESHOLD)


def test_spike_just_below_threshold_is_not_flagged():
    baseline_avg = 1_000
    results = detect_anomalies(
        current_by_group={"team-a": int(baseline_avg * DEFAULT_SPIKE_RATIO_THRESHOLD) - 1},
        baseline_total_by_group={"team-a": baseline_avg * 7},
        baseline_periods=7,
    )
    assert results == []


def test_new_spender_with_zero_baseline_is_flagged():
    results = detect_anomalies(
        current_by_group={"team-new": DEFAULT_MIN_FLOOR_CENTS + 1},
        baseline_total_by_group={},  # absent -> treated as zero baseline
        baseline_periods=7,
    )
    assert len(results) == 1
    assert results[0].code == "NEW_SPENDER"
    assert results[0].severity == "info"
    assert results[0].ratio is None
    assert results[0].baseline_avg_cents == 0.0


def test_below_floor_never_flagged_even_at_huge_ratio():
    # A $0.01 -> $0.05 jump is technically a 5x ratio but pure noise.
    results = detect_anomalies(
        current_by_group={"team-a": DEFAULT_MIN_FLOOR_CENTS - 1},
        baseline_total_by_group={},
        baseline_periods=7,
    )
    assert results == []


def test_groups_absent_from_current_are_never_evaluated():
    # A group with baseline history but nothing in the current window has nothing to
    # charge back or flag (this is about cost overruns, not underspend).
    results = detect_anomalies(
        current_by_group={},
        baseline_total_by_group={"team-a": 100_000},
        baseline_periods=7,
    )
    assert results == []


def test_results_sorted_by_current_spend_descending():
    results = detect_anomalies(
        current_by_group={"small": 5_000, "big": 50_000},
        baseline_total_by_group={},
        baseline_periods=7,
    )
    assert [r.group_key for r in results] == ["big", "small"]


def test_custom_threshold_and_floor_respected():
    results = detect_anomalies(
        current_by_group={"team-a": 2_500},
        baseline_total_by_group={"team-a": 1_000 * 7},
        baseline_periods=7,
        ratio_threshold=2.0,
        min_floor_cents=2_000,
    )
    assert len(results) == 1
    assert results[0].ratio == pytest.approx(2.5)
