"""D-020 pure schema validation (no DB)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from delta.executive.schemas import ExecutiveSummaryQuery

_TENANT = str(uuid.uuid4())
_START = datetime(2026, 7, 1, tzinfo=timezone.utc)
_END = _START + timedelta(days=7)


def test_executive_summary_query_accepts_valid_window() -> None:
    query = ExecutiveSummaryQuery(tenant_id=_TENANT, start=_START, end=_END)
    assert query.end > query.start


def test_executive_summary_query_rejects_end_before_start() -> None:
    with pytest.raises(ValidationError):
        ExecutiveSummaryQuery(tenant_id=_TENANT, start=_END, end=_START)


def test_executive_summary_query_rejects_equal_start_end() -> None:
    with pytest.raises(ValidationError):
        ExecutiveSummaryQuery(tenant_id=_TENANT, start=_START, end=_START)


def test_executive_summary_query_rejects_naive_start() -> None:
    with pytest.raises(ValidationError):
        ExecutiveSummaryQuery(tenant_id=_TENANT, start=datetime(2026, 7, 1), end=_END)


def test_executive_summary_query_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        ExecutiveSummaryQuery(tenant_id=_TENANT, start=_START, end=_END, unexpected="nope")
