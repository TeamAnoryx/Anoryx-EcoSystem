"""Period-window derivation (ADR-0005 §3.1)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from delta.budget import BudgetPeriod
from delta.budget_engine.periods import period_bucket_label, period_start

_T = datetime(2026, 7, 1, 14, 37, 53, 123456, tzinfo=timezone.utc)


def test_hourly_start_truncates_to_hour():
    assert period_start(BudgetPeriod.HOURLY, _T) == datetime(
        2026, 7, 1, 14, 0, 0, tzinfo=timezone.utc
    )


def test_daily_start_truncates_to_midnight():
    assert period_start(BudgetPeriod.DAILY, _T) == datetime(
        2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc
    )


def test_monthly_start_truncates_to_first_of_month():
    assert period_start(BudgetPeriod.MONTHLY, _T) == datetime(
        2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc
    )


def test_naive_datetime_assumed_utc():
    naive = datetime(2026, 7, 1, 14, 37, 53)
    assert period_start(BudgetPeriod.HOURLY, naive) == datetime(
        2026, 7, 1, 14, 0, 0, tzinfo=timezone.utc
    )


def test_bucket_label_is_iso_z():
    assert period_bucket_label(BudgetPeriod.DAILY, _T) == "2026-07-01T00:00:00Z"
    assert period_bucket_label(BudgetPeriod.HOURLY, _T) == "2026-07-01T14:00:00Z"


def test_non_utc_offset_normalized_to_utc():
    from datetime import timedelta

    plus2 = timezone(timedelta(hours=2))
    t = datetime(2026, 7, 1, 1, 30, 0, tzinfo=plus2)  # == 2026-06-30 23:30 UTC
    assert period_bucket_label(BudgetPeriod.DAILY, t) == "2026-06-30T00:00:00Z"


def test_period_end_is_next_boundary():
    from delta.budget_engine.periods import period_end

    assert period_end(BudgetPeriod.HOURLY, _T) == datetime(
        2026, 7, 1, 15, 0, 0, tzinfo=timezone.utc
    )
    assert period_end(BudgetPeriod.DAILY, _T) == datetime(2026, 7, 2, 0, 0, 0, tzinfo=timezone.utc)
    assert period_end(BudgetPeriod.MONTHLY, _T) == datetime(
        2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc
    )


def test_period_end_december_rolls_to_january():
    from delta.budget_engine.periods import period_end

    dec = datetime(2026, 12, 15, 9, 0, 0, tzinfo=timezone.utc)
    assert period_end(BudgetPeriod.MONTHLY, dec) == datetime(
        2027, 1, 1, 0, 0, 0, tzinfo=timezone.utc
    )


def test_period_start_and_end_reject_unknown_period():
    from delta.budget_engine.periods import period_end

    class _Fake:
        value = "weekly"

    with pytest.raises(ValueError):
        period_start(_Fake(), _T)
    with pytest.raises(ValueError):
        period_end(_Fake(), _T)
