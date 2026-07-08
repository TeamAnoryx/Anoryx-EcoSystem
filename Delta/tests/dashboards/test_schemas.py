"""D-008 pure schema validation — no DB."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from delta.dashboards.schemas import DashboardQuery, TopSpendersQuery

_NOW = datetime(2026, 7, 1, tzinfo=timezone.utc)


def _base(**over: object) -> dict:
    fields: dict = {
        "tenant_id": str(uuid.uuid4()),
        "start": _NOW,
        "end": _NOW + timedelta(days=1),
    }
    fields.update(over)
    return fields


def test_end_must_be_after_start() -> None:
    with pytest.raises(ValidationError, match="end must be strictly after start"):
        DashboardQuery(**_base(start=_NOW, end=_NOW))


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        DashboardQuery(**_base(start=datetime(2026, 7, 1), end=_NOW + timedelta(days=1)))


def test_window_exceeding_max_days_rejected() -> None:
    with pytest.raises(ValidationError, match="400-day maximum"):
        DashboardQuery(**_base(end=_NOW + timedelta(days=401)))


def test_ordinary_window_accepted() -> None:
    query = DashboardQuery(**_base())
    assert query.end > query.start


def test_group_by_same_as_pinned_scope_rejected() -> None:
    team_id = str(uuid.uuid4())
    with pytest.raises(ValidationError, match="cannot group_by=team_id"):
        TopSpendersQuery(**_base(team_id=team_id), group_by="team_id")


def test_group_by_different_dimension_than_scope_accepted() -> None:
    query = TopSpendersQuery(**_base(team_id=str(uuid.uuid4())), group_by="agent_id")
    assert query.group_by == "agent_id"
