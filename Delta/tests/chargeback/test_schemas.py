"""D-012 pure schema validation — no DB."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from delta.chargeback.schemas import AnomalyQuery, ChargebackQuery

_NOW = datetime(2026, 7, 1, tzinfo=timezone.utc)


def _base(**over: object) -> dict:
    fields: dict = {
        "tenant_id": str(uuid.uuid4()),
        "start": _NOW,
        "end": _NOW + timedelta(days=1),
        "group_by": "team_id",
    }
    fields.update(over)
    return fields


def test_end_must_be_after_start() -> None:
    with pytest.raises(ValidationError, match="end must be strictly after start"):
        ChargebackQuery(**_base(start=_NOW, end=_NOW))


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        ChargebackQuery(**_base(start=datetime(2026, 7, 1), end=_NOW + timedelta(days=1)))


def test_window_exceeding_max_days_rejected() -> None:
    with pytest.raises(ValidationError, match="400-day maximum"):
        ChargebackQuery(**_base(end=_NOW + timedelta(days=401)))


def test_window_of_exactly_400_days_plus_hours_rejected() -> None:
    with pytest.raises(ValidationError, match="400-day maximum"):
        ChargebackQuery(**_base(end=_NOW + timedelta(days=400, hours=23, minutes=59)))


def test_group_by_same_as_pinned_scope_rejected() -> None:
    team_id = str(uuid.uuid4())
    with pytest.raises(ValidationError, match="cannot group_by=team_id"):
        ChargebackQuery(**_base(team_id=team_id, group_by="team_id"))


def test_group_by_different_dimension_than_scope_accepted() -> None:
    query = ChargebackQuery(**_base(team_id=str(uuid.uuid4()), group_by="agent_id"))
    assert query.group_by == "agent_id"


def test_anomaly_query_default_baseline_periods() -> None:
    query = AnomalyQuery(**_base())
    assert query.baseline_periods == 7


def test_anomaly_query_baseline_periods_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        AnomalyQuery(**_base(baseline_periods=0))
    with pytest.raises(ValidationError):
        AnomalyQuery(**_base(baseline_periods=91))


def test_anomaly_query_baseline_window_is_n_windows_immediately_before_start() -> None:
    query = AnomalyQuery(**_base(baseline_periods=3))  # 1-day window x 3
    baseline_start, baseline_end = query.baseline_window()
    assert baseline_end == query.start
    assert baseline_start == query.start - timedelta(days=3)


def test_anomaly_query_bounded_total_baseline_span_rejected() -> None:
    # 200-day window x 3 baseline_periods = 600 days > the 400-day cap.
    with pytest.raises(ValidationError, match="maximum total baseline span"):
        AnomalyQuery(**_base(end=_NOW + timedelta(days=200), baseline_periods=3))


def test_anomaly_query_bounded_total_baseline_span_accepted_at_the_edge() -> None:
    # 100-day window x 4 baseline_periods = exactly 400 days -> accepted.
    query = AnomalyQuery(**_base(end=_NOW + timedelta(days=100), baseline_periods=4))
    assert query.baseline_periods == 4
