"""Burn-rate derivation — vector 5 (never stored; recompute matches; window-bounded)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from delta.burn_rate import BurnRate, burn_rate
from delta.usage import TimeWindow, UsageRecord, WindowGranularity

_TENANT = "66666666-6666-4666-8666-666666666666"


def _usage(
    ts: datetime,
    cents: int,
    tin: int = 10,
    tout: int = 20,
    currency: str = "USD",
    tenant: str = _TENANT,
) -> UsageRecord:
    return UsageRecord(
        tenant_id=tenant,
        team_id="77777777-7777-4777-8777-777777777777",
        project_id="88888888-8888-4888-8888-888888888888",
        agent_id="gateway-core",
        model="gpt-4o",
        tokens_in=tin,
        tokens_out=tout,
        cost_estimate_cents=cents,
        currency=currency,
        request_id="req-1",
        event_id="99999999-9999-4999-8999-999999999999",
        event_timestamp=ts,
    )


def _window() -> TimeWindow:
    return TimeWindow(
        start=datetime(2026, 6, 26, 0, 0, 0, tzinfo=timezone.utc),
        end=datetime(2026, 6, 26, 2, 0, 0, tzinfo=timezone.utc),  # 2-hour window
        granularity=WindowGranularity.HOURLY,
    )


def test_burn_rate_sums_exact_integer_cost():
    win = _window()
    records = [
        _usage(datetime(2026, 6, 26, 0, 30, tzinfo=timezone.utc), cents=300, tin=10, tout=5),
        _usage(datetime(2026, 6, 26, 1, 30, tzinfo=timezone.utc), cents=500, tin=20, tout=10),
    ]
    br = burn_rate(records, win)
    assert br.total_cost_cents == 800  # exact integer
    assert br.total_tokens == 45
    assert br.sample_count == 2
    assert br.cost_cents_per_hour == 400.0  # 800 cents / 2 hours (derived rate)
    assert br.tokens_per_hour == 22.5


def test_burn_rate_excludes_out_of_window():
    win = _window()
    records = [
        _usage(datetime(2026, 6, 25, 23, 0, tzinfo=timezone.utc), cents=999),  # before start
        _usage(datetime(2026, 6, 26, 1, 0, tzinfo=timezone.utc), cents=100),  # inside
        _usage(
            datetime(2026, 6, 26, 2, 0, tzinfo=timezone.utc), cents=999
        ),  # == end (half-open, excluded)
    ]
    br = burn_rate(records, win)
    assert br.total_cost_cents == 100
    assert br.sample_count == 1


def test_burn_rate_empty_window():
    br = burn_rate([], _window())
    assert br.total_cost_cents == 0
    assert br.total_tokens == 0
    assert br.sample_count == 0
    assert br.currency is None


def test_burn_rate_is_recomputed_not_stored():
    # Vector 5: the same inputs always recompute the same result; nothing is cached
    # or stored on the source records, so a burn-rate can't desync from the ledger.
    win = _window()
    records = [_usage(datetime(2026, 6, 26, 0, 30, tzinfo=timezone.utc), cents=250)]
    assert burn_rate(records, win) == burn_rate(records, win)
    # UsageRecord carries no burn-rate field to forge.
    assert "burn" not in UsageRecord.model_fields


def test_burn_rate_mixed_currency_rejected():
    win = _window()
    records = [
        _usage(datetime(2026, 6, 26, 0, 30, tzinfo=timezone.utc), cents=100, currency="USD"),
        _usage(datetime(2026, 6, 26, 1, 30, tzinfo=timezone.utc), cents=100, currency="EUR"),
    ]
    with pytest.raises(ValueError, match="mixed-currency"):
        burn_rate(records, win)


def test_burn_rate_result_is_frozen():
    br = burn_rate([], _window())
    assert isinstance(br, BurnRate)
    with pytest.raises(ValidationError):
        br.total_cost_cents = 999  # type: ignore[misc]


def test_burn_rate_attributes_single_tenant():
    win = _window()
    records = [_usage(datetime(2026, 6, 26, 0, 30, tzinfo=timezone.utc), cents=100)]
    assert burn_rate(records, win).tenant_id == _TENANT


def test_burn_rate_mixed_tenant_rejected():
    # Vector 7: a window holding two tenants cannot be summed into one rate.
    win = _window()
    other = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    records = [
        _usage(datetime(2026, 6, 26, 0, 30, tzinfo=timezone.utc), cents=100, tenant=_TENANT),
        _usage(datetime(2026, 6, 26, 1, 30, tzinfo=timezone.utc), cents=100, tenant=other),
    ]
    with pytest.raises(ValueError, match="mixed-tenant"):
        burn_rate(records, win)


def test_burn_rate_field_rejects_float_on_direct_construction():
    # Vector 1: total_cost_cents is money; a float must be rejected even when a
    # caller builds BurnRate directly (not just via burn_rate()).
    with pytest.raises(ValidationError):
        BurnRate(
            window=_window(),
            tenant_id=_TENANT,
            currency="USD",
            sample_count=1,
            total_cost_cents=1.0,
            total_tokens=0,
        )


def test_burn_rate_field_rejects_negative():
    # L-2: negative money/count nonsensical even on direct construction.
    with pytest.raises(ValidationError):
        BurnRate(
            window=_window(),
            tenant_id=_TENANT,
            currency="USD",
            sample_count=1,
            total_cost_cents=-100,
            total_tokens=0,
        )


def test_burn_rate_field_rejects_overflow():
    # L-2: above the budget wire maximum sanity ceiling.
    with pytest.raises(ValidationError):
        BurnRate(
            window=_window(),
            tenant_id=_TENANT,
            currency="USD",
            sample_count=1,
            total_cost_cents=0,
            total_tokens=10**20,
        )


def test_timewindow_rejects_reversed():
    with pytest.raises(ValueError):
        TimeWindow(
            start=datetime(2026, 6, 26, 2, 0, tzinfo=timezone.utc),
            end=datetime(2026, 6, 26, 1, 0, tzinfo=timezone.utc),
            granularity=WindowGranularity.HOURLY,
        )
