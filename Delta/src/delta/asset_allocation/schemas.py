"""Asset-allocation recommendation API DTOs (D-023, ADR-0023).

Builds on D-021's `personal_accounts` (a recommendation always targets an existing
account of type "investment") and its "B2C consumer IS one `tenant_id`" convention
(ADR-0021 Fork 1) — no new identity model here either.

No client-supplied monetary field exists in this package (unlike `personal_finance`'s
`TransactionCreateRequest`/`BudgetCreateRequest`): every dollar figure in a response is
computed server-side from the tenant's own recorded transactions, never accepted on the
wire. Same reasoning: no free-text field exists either (no name/description/note), so
neither `reject_non_integer` nor the control-character rejection helper every other
Delta schemas module carries is needed here — a deliberate absence, not an oversight.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from ..identifiers import AllocationRecommendationId, PersonalAccountId, TenantId
from ..money import Currency, require_aware_utc

RiskTier = Literal["conservative", "moderate", "aggressive"]

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500

# Fixed, deterministic target-allocation percentages per risk tier (ADR-0023 Fork 2) —
# a disclosed rules-based table, NOT machine learning / AI and NOT a live market-data-
# driven or age/glide-path model. Each tier's three percentages sum to exactly 100 (also
# enforced by a DB CHECK, migration 0016, and by test_schemas.py at the unit level).
RISK_TIER_TARGET_ALLOCATION_PCT: dict[RiskTier, dict[str, int]] = {
    "conservative": {"cash_pct": 40, "bonds_pct": 40, "equities_pct": 20},
    "moderate": {"cash_pct": 20, "bonds_pct": 30, "equities_pct": 50},
    "aggressive": {"cash_pct": 10, "bonds_pct": 15, "equities_pct": 75},
}

# Fixed fraction of a positive surplus recommended as a one-time micro-investment
# (ADR-0023 Fork 3) — a disclosed constant, not a personalized/predicted figure.
MICRO_INVESTMENT_SURPLUS_RATE = 0.10


class RiskTierAllocationView(BaseModel):
    """One risk tier's disclosed target-allocation percentages (pure, no DB)."""

    model_config = ConfigDict(extra="forbid")

    risk_tier: RiskTier
    cash_pct: int
    bonds_pct: int
    equities_pct: int


class AllocationRecommendationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    account_id: PersonalAccountId
    risk_tier: RiskTier
    period_start: datetime
    period_end: datetime

    @model_validator(mode="after")
    def _validate_period(self) -> "AllocationRecommendationRequest":
        require_aware_utc(self.period_start, "period_start")
        require_aware_utc(self.period_end, "period_end")
        if self.period_end <= self.period_start:
            raise ValueError("period_end must be after period_start")
        return self


class AllocationRecommendationView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recommendation_id: AllocationRecommendationId
    tenant_id: TenantId
    account_id: PersonalAccountId
    risk_tier: RiskTier
    cash_pct: int
    bonds_pct: int
    equities_pct: int
    period_start: datetime
    period_end: datetime
    # Net income-minus-expense across the tenant's personal_transactions in the window
    # (may be negative or zero — never clamped/hidden, mirrors D-021's honesty rule of
    # showing an absent/negative signal rather than silently reweighting it).
    surplus_minor_units: int
    # A fixed MICRO_INVESTMENT_SURPLUS_RATE of `surplus_minor_units`, floored to integer
    # minor units, and floored to exactly 0 whenever surplus_minor_units <= 0 (never a
    # negative or fabricated recommendation).
    recommended_micro_investment_minor_units: int
    currency: Currency
    # A DETERMINISTIC, versioned method tag (mirrors D-011/D-012's honesty-tagging
    # precedent) — NOT machine learning / AI. See ADR-0023 §2 for the exact formula.
    method: Literal["risk_tier_target_allocation_v1"] = "risk_tier_target_allocation_v1"
    computed_at: datetime
