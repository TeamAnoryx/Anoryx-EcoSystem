"""Pure burn-rate projection arithmetic (D-011, ADR-0011 §2 fork 1).

No I/O, no budget-cap knowledge (that lives in :mod:`.recommendations`, which combines a
:class:`Projection` with a ``BudgetDefinition``'s cap). Deliberately NOT a linear
regression / least-squares fit over a bucketed time series: with as few as 2-3 daily
buckets (early in a period) a fitted slope is extremely sensitive to a single noisy point
and can extrapolate a wild, misleading forecast. Instead this uses the CURRENT PERIOD's
own average rate so far (``spend_so_far / hours_elapsed``) projected forward at a constant
rate — the exact same "flat average" concept D-008's ``burn_rate_cents_per_hour`` already
uses, extended from "the current rate" to "the current rate, held constant to project
period-end spend." This is simpler, more robust to sparse/noisy data, and easier to reason
about than a regression — see the ADR's honesty-boundary section for the full rationale.

All spend figures here are the same "client-side cost estimate" framing D-008/D-005 use
throughout Delta — a projection, not a guarantee, and (see :mod:`.recommendations`) never
fed back into an actual enforcement decision (those stay strictly integer, per
``budget_engine.decision``'s own invariant).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

TrendDirection = Literal["rising", "falling", "flat"]

# Below this much elapsed time in the period, a burn rate is too noisy/undefined to
# project (e.g. a monthly budget one hour into a fresh period) — report insufficient
# data honestly rather than extrapolate from near-zero elapsed time.
MIN_ELAPSED_HOURS_FOR_PROJECTION = 1.0

# A trend direction is only reported once there are two MEANINGFUL halves to compare
# (each at least MIN_ELAPSED_HOURS_FOR_PROJECTION long).
_MIN_ELAPSED_HOURS_FOR_TREND = MIN_ELAPSED_HOURS_FOR_PROJECTION * 2

# Second-half vs first-half rate must differ by more than this factor to be labeled a
# trend at all — avoids a noise-driven "rising"/"falling" flip on a near-flat rate.
_TREND_RISING_FACTOR = 1.2
_TREND_FALLING_FACTOR = 0.8


@dataclass(frozen=True)
class Projection:
    period_start: datetime
    period_end: datetime
    elapsed_hours: float
    remaining_hours: float
    current_period_spend_cents: int
    burn_rate_cents_per_hour: float
    projected_period_end_spend_cents: float | None
    trend_direction: TrendDirection | None
    insufficient_data: bool


def compute_projection(
    *,
    period_start: datetime,
    period_end: datetime,
    now: datetime,
    current_period_spend_cents: int,
    first_half_spend_cents: int,
    second_half_spend_cents: int,
) -> Projection:
    """Project ``current_period_spend_cents`` forward to ``period_end`` at the current rate.

    ``first_half_spend_cents``/``second_half_spend_cents`` are the caller's own two equal
    time-halves of ``[period_start, now)`` (only meaningful once elapsed time clears
    :data:`_MIN_ELAPSED_HOURS_FOR_TREND` — the caller may pass 0/0 otherwise, which this
    function ignores by not computing a trend).
    """
    elapsed_hours = max(0.0, (now - period_start).total_seconds() / 3600.0)
    remaining_hours = max(0.0, (period_end - now).total_seconds() / 3600.0)

    if elapsed_hours < MIN_ELAPSED_HOURS_FOR_PROJECTION:
        return Projection(
            period_start=period_start,
            period_end=period_end,
            elapsed_hours=elapsed_hours,
            remaining_hours=remaining_hours,
            current_period_spend_cents=current_period_spend_cents,
            burn_rate_cents_per_hour=0.0,
            projected_period_end_spend_cents=None,
            trend_direction=None,
            insufficient_data=True,
        )

    burn_rate_cents_per_hour = current_period_spend_cents / elapsed_hours
    projected_period_end_spend_cents = (
        current_period_spend_cents + burn_rate_cents_per_hour * remaining_hours
    )

    trend_direction: TrendDirection | None = None
    if elapsed_hours >= _MIN_ELAPSED_HOURS_FOR_TREND:
        half_hours = elapsed_hours / 2.0
        first_rate = first_half_spend_cents / half_hours
        second_rate = second_half_spend_cents / half_hours
        if second_rate > first_rate * _TREND_RISING_FACTOR:
            trend_direction = "rising"
        elif second_rate < first_rate * _TREND_FALLING_FACTOR:
            trend_direction = "falling"
        else:
            trend_direction = "flat"

    return Projection(
        period_start=period_start,
        period_end=period_end,
        elapsed_hours=elapsed_hours,
        remaining_hours=remaining_hours,
        current_period_spend_cents=current_period_spend_cents,
        burn_rate_cents_per_hour=burn_rate_cents_per_hour,
        projected_period_end_spend_cents=projected_period_end_spend_cents,
        trend_direction=trend_direction,
        insufficient_data=False,
    )


def exhaustion_at(
    *,
    now: datetime,
    period_end: datetime,
    current_period_spend_cents: int,
    cap_cost_cents: int,
    burn_rate_cents_per_hour: float,
) -> datetime | None:
    """When spend is projected to cross ``cap_cost_cents``, at the current rate.

    ``None`` when already over the cap (that's ``ALREADY_OVER_CAP`` territory, not a
    future projection), the rate is non-positive (never crosses forward), or the
    projected crossing falls at/after ``period_end`` (the period resets before it would
    happen — not a meaningful forecast for THIS period).
    """
    if burn_rate_cents_per_hour <= 0 or current_period_spend_cents >= cap_cost_cents:
        return None
    hours_until = (cap_cost_cents - current_period_spend_cents) / burn_rate_cents_per_hour
    candidate = now + timedelta(hours=hours_until)
    return candidate if candidate < period_end else None
