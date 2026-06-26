"""Burn-rate as a derivation over the usage time-series (vector 5).

Burn-rate is NEVER a stored field on any domain type — it is recomputed from the
underlying ``UsageRecord`` series each call, so it cannot desync from or be forged
against the source of truth. The returned ``BurnRate`` holds the **exact integer**
cost/token totals; the per-hour figures are derived *rates* (ratios), exposed as
properties, not stored monetary amounts.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, field_validator

from .identifiers import TenantId
from .money import MAX_BUDGET_COST_CENTS, MAX_BUDGET_TOKENS, Currency, bounded_count
from .usage import TimeWindow, UsageRecord

_SECONDS_PER_HOUR = 3600.0


class BurnRate(BaseModel):
    """A derived view of spend/throughput over a window. Exact integer totals;
    per-hour figures are derived rates, not money."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    window: TimeWindow
    tenant_id: TenantId | None  # the single tenant of the window; None when empty
    currency: Currency | None  # None when the window holds no samples
    sample_count: int
    total_cost_cents: int
    total_tokens: int

    # Bounded non-negative integers even on direct construction (not just via the
    # burn_rate() factory): floats/bools forbidden (the module invariant), no
    # negatives, capped at the budget wire maxima as a sanity ceiling.
    @field_validator("total_cost_cents", mode="before")
    @classmethod
    def _cost(cls, value: object) -> int:
        return bounded_count(value, "total_cost_cents", MAX_BUDGET_COST_CENTS)

    @field_validator("total_tokens", mode="before")
    @classmethod
    def _tokens(cls, value: object) -> int:
        return bounded_count(value, "total_tokens", MAX_BUDGET_TOKENS)

    @field_validator("sample_count", mode="before")
    @classmethod
    def _count(cls, value: object) -> int:
        return bounded_count(value, "sample_count", MAX_BUDGET_TOKENS)

    @property
    def cost_cents_per_hour(self) -> float:
        return self.total_cost_cents / (self.window.duration_seconds / _SECONDS_PER_HOUR)

    @property
    def tokens_per_hour(self) -> float:
        return self.total_tokens / (self.window.duration_seconds / _SECONDS_PER_HOUR)


def burn_rate(records: Sequence[UsageRecord], window: TimeWindow) -> BurnRate:
    """Derive the burn-rate of ``records`` over the half-open ``[start, end)`` window.

    Only records whose ``event_timestamp`` falls in the window count. Cost/token
    totals are exact integer sums. A window spanning more than one tenant_id
    (vector 7) or more than one currency (Fork 4) cannot be summed into a single
    figure and is rejected. The result is attributed to the window's single tenant.
    """
    in_window = [r for r in records if window.start <= r.event_timestamp < window.end]

    # Vector 7: a burn-rate is a single-tenant aggregate. A window spanning more
    # than one tenant_id cannot be summed into one figure and is rejected, so a
    # caller (D-003) cannot silently blend tenants into one rate.
    tenants = {r.tenant_id for r in in_window}
    if len(tenants) > 1:
        raise ValueError(f"mixed-tenant burn-rate window rejected: {len(tenants)} tenants")

    currencies = {r.currency for r in in_window}
    if len(currencies) > 1:
        raise ValueError(f"mixed-currency burn-rate window rejected: {sorted(currencies)}")

    total_cost = sum(r.cost_estimate_cents for r in in_window)
    total_tokens = sum(r.tokens_in + r.tokens_out for r in in_window)
    return BurnRate(
        window=window,
        tenant_id=next(iter(tenants)) if tenants else None,
        currency=next(iter(currencies)) if currencies else None,
        sample_count=len(in_window),
        total_cost_cents=total_cost,
        total_tokens=total_tokens,
    )
