"""Period-window derivation for budget evaluation (ADR-0005 §3.1).

A budget resets on its ``period`` boundary (hourly/daily/monthly). Spend is summed over
the half-open window ``[period_start, period_end)`` (the whole current period — see
``spend.scope_spend_cents``: net debit−credit over the tenant's expense accounts) and the
enforcement-state row is keyed by the window so a new period naturally starts ``under`` (a
fresh budget). All boundaries are computed in UTC; the bucket label is the ISO-8601 ``Z``
form of ``period_start``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..budget import BudgetPeriod


def _as_utc(now: datetime) -> datetime:
    """Coerce to a tz-aware UTC datetime (a naive value is assumed UTC)."""
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def period_start(period: BudgetPeriod, now: datetime) -> datetime:
    """The start of the current budget window containing ``now`` (UTC, inclusive)."""
    u = _as_utc(now)
    if period is BudgetPeriod.HOURLY:
        return u.replace(minute=0, second=0, microsecond=0)
    if period is BudgetPeriod.DAILY:
        return u.replace(hour=0, minute=0, second=0, microsecond=0)
    if period is BudgetPeriod.MONTHLY:
        return u.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"unknown budget period: {period!r}")


def period_end(period: BudgetPeriod, now: datetime) -> datetime:
    """The start of the NEXT window (exclusive upper bound of the current window, UTC).

    Spend is summed over ``[period_start, period_end)`` — the whole current period — so an
    event timestamped within this period but slightly ahead of the eval clock still counts.
    """
    start = period_start(period, now)
    if period is BudgetPeriod.HOURLY:
        return start + timedelta(hours=1)
    if period is BudgetPeriod.DAILY:
        return start + timedelta(days=1)
    if period is BudgetPeriod.MONTHLY:
        # First day of the next month (handle December → January rollover).
        if start.month == 12:
            return start.replace(year=start.year + 1, month=1)
        return start.replace(month=start.month + 1)
    raise ValueError(f"unknown budget period: {period!r}")


def period_bucket_label(period: BudgetPeriod, now: datetime) -> str:
    """A stable string key for the current window (the ISO ``Z`` form of period_start)."""
    start = period_start(period, now)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")
