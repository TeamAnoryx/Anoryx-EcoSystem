"""Pure projection arithmetic: no I/O, no DB (D-011, ADR-0011 §2 fork 1)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from delta.forecasting.projection import compute_projection, exhaustion_at

_START = datetime(2026, 7, 1, tzinfo=timezone.utc)
_END = datetime(2026, 8, 1, tzinfo=timezone.utc)  # 31-day month


def test_insufficient_data_under_one_hour_elapsed():
    now = _START + timedelta(minutes=30)
    p = compute_projection(
        period_start=_START,
        period_end=_END,
        now=now,
        current_period_spend_cents=500,
        first_half_spend_cents=0,
        second_half_spend_cents=0,
    )
    assert p.insufficient_data is True
    assert p.burn_rate_cents_per_hour == 0.0
    assert p.projected_period_end_spend_cents is None
    assert p.trend_direction is None


def test_flat_rate_projection_matches_hand_calculation():
    # 10 days elapsed, $100/day spent flat -> $10/hr; 21 days (504h) remaining.
    now = _START + timedelta(days=10)
    current_spend = 100_00 * 10  # $1000 in cents
    p = compute_projection(
        period_start=_START,
        period_end=_END,
        now=now,
        current_period_spend_cents=current_spend,
        first_half_spend_cents=current_spend // 2,
        second_half_spend_cents=current_spend // 2,
    )
    assert p.insufficient_data is False
    expected_rate = current_spend / (10 * 24)
    assert p.burn_rate_cents_per_hour == expected_rate
    expected_projection = current_spend + expected_rate * (21 * 24)
    assert p.projected_period_end_spend_cents == expected_projection
    assert p.trend_direction == "flat"  # first/second half equal


def test_rising_trend_detected_when_second_half_meaningfully_higher():
    now = _START + timedelta(days=10)
    p = compute_projection(
        period_start=_START,
        period_end=_END,
        now=now,
        current_period_spend_cents=1500_00,
        first_half_spend_cents=500_00,  # $500 in the first 5 days
        second_half_spend_cents=1000_00,  # $1000 in the next 5 days -> 2x rate
    )
    assert p.trend_direction == "rising"


def test_falling_trend_detected_when_second_half_meaningfully_lower():
    now = _START + timedelta(days=10)
    p = compute_projection(
        period_start=_START,
        period_end=_END,
        now=now,
        current_period_spend_cents=1500_00,
        first_half_spend_cents=1000_00,
        second_half_spend_cents=500_00,
    )
    assert p.trend_direction == "falling"


def test_trend_within_20_percent_band_is_flat_not_noise():
    now = _START + timedelta(days=10)
    p = compute_projection(
        period_start=_START,
        period_end=_END,
        now=now,
        current_period_spend_cents=1100_00,
        first_half_spend_cents=500_00,
        second_half_spend_cents=600_00,  # 1.2x — right at the rising threshold boundary
    )
    # Strictly greater than 1.2x is required to call it "rising" (not >=).
    assert p.trend_direction == "flat"


def test_no_trend_direction_before_two_hours_elapsed():
    # Elapsed clears the 1h insufficient-data bar but not the 2h trend bar.
    now = _START + timedelta(hours=1, minutes=30)
    p = compute_projection(
        period_start=_START,
        period_end=_END,
        now=now,
        current_period_spend_cents=100,
        first_half_spend_cents=0,
        second_half_spend_cents=0,
    )
    assert p.insufficient_data is False
    assert p.trend_direction is None


def test_zero_spend_projects_to_zero():
    now = _START + timedelta(days=5)
    p = compute_projection(
        period_start=_START,
        period_end=_END,
        now=now,
        current_period_spend_cents=0,
        first_half_spend_cents=0,
        second_half_spend_cents=0,
    )
    assert p.burn_rate_cents_per_hour == 0.0
    assert p.projected_period_end_spend_cents == 0.0
    assert p.trend_direction == "flat"


# --------------------------------------------------------------------------- exhaustion_at


def test_exhaustion_at_projects_forward_correctly():
    now = _START + timedelta(days=10)
    rate = 1000_00 / (10 * 24)  # $1000 spent over 240h -> ~$4.17/hr
    # $1000 remaining ($2000 cap - $1000 spent) / rate -> 240h until crossing.
    result = exhaustion_at(
        now=now,
        period_end=_END,
        current_period_spend_cents=1000_00,
        cap_cost_cents=2000_00,
        burn_rate_cents_per_hour=rate,
    )
    assert result is not None
    assert result == now + timedelta(hours=(1000_00 / rate))


def test_exhaustion_at_none_when_already_over_cap():
    now = _START + timedelta(days=10)
    result = exhaustion_at(
        now=now,
        period_end=_END,
        current_period_spend_cents=3000_00,
        cap_cost_cents=2000_00,
        burn_rate_cents_per_hour=100.0,
    )
    assert result is None


def test_exhaustion_at_none_when_rate_non_positive():
    now = _START + timedelta(days=10)
    assert (
        exhaustion_at(
            now=now,
            period_end=_END,
            current_period_spend_cents=100,
            cap_cost_cents=2000_00,
            burn_rate_cents_per_hour=0.0,
        )
        is None
    )


def test_exhaustion_at_none_when_crossing_falls_after_period_end():
    now = _START + timedelta(days=30)  # 1 day left in a 31-day month
    # Rate so slow the crossing wouldn't happen until well past period_end.
    result = exhaustion_at(
        now=now,
        period_end=_END,
        current_period_spend_cents=100_00,
        cap_cost_cents=200_00,
        burn_rate_cents_per_hour=1.0,  # would take >4000 hours to close a $100 gap
    )
    assert result is None
