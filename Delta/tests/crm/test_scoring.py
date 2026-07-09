"""Pure unit tests for the D-013 relationship-scoring heuristic — no DB, no I/O."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from delta.crm.scoring import compute_relationship_score, days_since

_NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)


def test_no_engagement_scores_zero() -> None:
    result = compute_relationship_score(
        interaction_count_90d=0, days_since_last_interaction=None, open_deal_count=0
    )
    assert result.score == 0.0
    assert result.method == "recency_frequency_v1"


def test_recency_full_marks_within_a_week() -> None:
    result = compute_relationship_score(
        interaction_count_90d=0, days_since_last_interaction=7, open_deal_count=0
    )
    assert result.score == 50.0


def test_recency_drops_to_partial_credit_just_past_a_week() -> None:
    result = compute_relationship_score(
        interaction_count_90d=0, days_since_last_interaction=8, open_deal_count=0
    )
    assert result.score == 30.0


def test_recency_partial_credit_at_thirty_days() -> None:
    result = compute_relationship_score(
        interaction_count_90d=0, days_since_last_interaction=30, open_deal_count=0
    )
    assert result.score == 30.0


def test_recency_minimal_credit_just_past_thirty_days() -> None:
    result = compute_relationship_score(
        interaction_count_90d=0, days_since_last_interaction=31, open_deal_count=0
    )
    assert result.score == 10.0


def test_recency_minimal_credit_at_ninety_days() -> None:
    result = compute_relationship_score(
        interaction_count_90d=0, days_since_last_interaction=90, open_deal_count=0
    )
    assert result.score == 10.0


def test_recency_zero_past_ninety_days() -> None:
    result = compute_relationship_score(
        interaction_count_90d=0, days_since_last_interaction=91, open_deal_count=0
    )
    assert result.score == 0.0


def test_frequency_zero_interactions_scores_zero() -> None:
    result = compute_relationship_score(
        interaction_count_90d=0, days_since_last_interaction=None, open_deal_count=0
    )
    assert result.score == 0.0


def test_frequency_low_tier() -> None:
    result = compute_relationship_score(
        interaction_count_90d=2, days_since_last_interaction=None, open_deal_count=0
    )
    assert result.score == 10.0


def test_frequency_mid_tier() -> None:
    result = compute_relationship_score(
        interaction_count_90d=5, days_since_last_interaction=None, open_deal_count=0
    )
    assert result.score == 25.0


def test_frequency_high_tier() -> None:
    result = compute_relationship_score(
        interaction_count_90d=6, days_since_last_interaction=None, open_deal_count=0
    )
    assert result.score == 40.0


def test_pipeline_one_open_deal() -> None:
    result = compute_relationship_score(
        interaction_count_90d=0, days_since_last_interaction=None, open_deal_count=1
    )
    assert result.score == 5.0


def test_pipeline_multiple_open_deals_caps_at_ten() -> None:
    result = compute_relationship_score(
        interaction_count_90d=0, days_since_last_interaction=None, open_deal_count=5
    )
    assert result.score == 10.0


def test_max_score_is_exactly_one_hundred() -> None:
    result = compute_relationship_score(
        interaction_count_90d=10, days_since_last_interaction=0, open_deal_count=3
    )
    assert result.score == 100.0


def test_score_is_never_above_one_hundred() -> None:
    # Guards the min(100.0, ...) clamp even though the component maxima already sum
    # to exactly 100 — a future rebalancing of the tiers should not silently exceed it.
    result = compute_relationship_score(
        interaction_count_90d=1000, days_since_last_interaction=0, open_deal_count=1000
    )
    assert result.score == 100.0


def test_days_since_none_when_no_prior_interaction() -> None:
    assert days_since(now=_NOW, last_interaction_at=None) is None


def test_days_since_computes_whole_days() -> None:
    ten_days_ago = _NOW - timedelta(days=10, hours=3)
    assert days_since(now=_NOW, last_interaction_at=ten_days_ago) == 10


def test_days_since_floors_at_zero_for_future_timestamp() -> None:
    # Clock skew / same-instant edge case — never a negative "days ago".
    future = _NOW + timedelta(hours=1)
    assert days_since(now=_NOW, last_interaction_at=future) == 0
