"""Relationship-scoring heuristic (D-013, ADR-0013 Fork 1).

A deterministic recency + frequency + open-pipeline heuristic, deliberately NOT a
trained/validated statistical or ML model — the same "no forecasting/ML precedent
anywhere in this ecosystem" reasoning D-011's ADR established for budget forecasting
and D-012's ADR established for anomaly detection. Pure function, no I/O: every input
is a small, already-computed aggregate (``delta.crm.store.get_client_engagement_summary``),
never a raw interaction/deal list.

Score = recency_score + frequency_score + pipeline_score, each a fixed step function
over a bounded input, summing to a maximum of exactly 100. Method is a literal,
versioned tag (``recency_frequency_v1``) — a future different method gets a NEW
literal, never a silent redefinition of this one (mirrors D-011's
``current_rate_projection_v1`` / D-012's ``trailing_average_ratio_v1``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

RelationshipScoreMethod = Literal["recency_frequency_v1"]

# Recency component (0-50): how recently the client was last engaged.
_RECENCY_MAX = 50.0
_RECENCY_FULL_DAYS = 7  # full marks within a week
_RECENCY_PARTIAL_DAYS = 30  # partial credit within a month
_RECENCY_MINIMAL_DAYS = 90  # minimal credit within a quarter

# Frequency component (0-40): interaction volume in the trailing 90-day window.
_FREQUENCY_MAX = 40.0

# Open-pipeline component (0-10): active deals in flight.
_PIPELINE_MAX = 10.0


@dataclass(frozen=True)
class RelationshipScoreResult:
    score: float
    method: RelationshipScoreMethod


def _recency_score(days_since_last_interaction: int | None) -> float:
    if days_since_last_interaction is None:
        return 0.0
    if days_since_last_interaction <= _RECENCY_FULL_DAYS:
        return 50.0
    if days_since_last_interaction <= _RECENCY_PARTIAL_DAYS:
        return 30.0
    if days_since_last_interaction <= _RECENCY_MINIMAL_DAYS:
        return 10.0
    return 0.0


def _frequency_score(interaction_count_90d: int) -> float:
    if interaction_count_90d <= 0:
        return 0.0
    if interaction_count_90d <= 2:
        return 10.0
    if interaction_count_90d <= 5:
        return 25.0
    return 40.0


def _pipeline_score(open_deal_count: int) -> float:
    if open_deal_count <= 0:
        return 0.0
    if open_deal_count == 1:
        return 5.0
    return 10.0


def days_since(*, now: datetime, last_interaction_at: datetime | None) -> int | None:
    """Whole days elapsed since ``last_interaction_at`` (None if there is none yet).
    Floors at 0 — a same-instant or clock-skewed "future" interaction is not scored as
    negative recency."""
    if last_interaction_at is None:
        return None
    delta = now - last_interaction_at
    return max(0, delta.days)


def compute_relationship_score(
    *,
    interaction_count_90d: int,
    days_since_last_interaction: int | None,
    open_deal_count: int,
) -> RelationshipScoreResult:
    """Deterministic, explainable score in ``[0, 100]``. Every input is a small,
    already-bounded integer/day-count — no unbounded list is scanned here."""
    total = (
        _recency_score(days_since_last_interaction)
        + _frequency_score(interaction_count_90d)
        + _pipeline_score(open_deal_count)
    )
    return RelationshipScoreResult(score=min(100.0, total), method="recency_frequency_v1")
