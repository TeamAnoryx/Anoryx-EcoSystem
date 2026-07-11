"""Investment holding + allocation-recommendation API DTOs (D-023, ADR-0023).

Mirrors D-021's ``personal_finance.schemas`` conventions throughout (bounded
tenant-scoped requests, ``require_aware_utc`` window validation, control-character
rejection on any free text). A holding's ``value_minor_units`` is exactly what the
caller declares — no live market-data/pricing feed exists anywhere in this codebase
(ADR-0023 Sec 1).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..identifiers import InvestmentHoldingId, PersonalAccountId, TenantId
from ..money import Currency, reject_non_integer, require_aware_utc

AssetClass = Literal["stocks", "bonds", "cash_equivalents", "real_estate", "crypto", "other"]
# Fixed, disclosed iteration order — every list-shaped response (allocation lines)
# uses this order, so a caller can index/compare responses positionally.
ASSET_CLASSES: tuple[AssetClass, ...] = (
    "stocks",
    "bonds",
    "cash_equivalents",
    "real_estate",
    "crypto",
    "other",
)

RiskProfile = Literal["conservative", "moderate", "aggressive"]
RebalanceAction = Literal["buy", "sell", "hold"]

# Same order of magnitude as every other Delta monetary field's overflow guard
# (mirrors personal_finance.schemas.MAX_AMOUNT_MINOR_UNITS).
MAX_AMOUNT_MINOR_UNITS = 100_000_000_000  # 1e11 minor units

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


class HoldingRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    account_id: PersonalAccountId
    asset_class: AssetClass
    value_minor_units: int = Field(ge=0, le=MAX_AMOUNT_MINOR_UNITS)
    currency: Currency

    @field_validator("value_minor_units", mode="before")
    @classmethod
    def _value_strict_integer(cls, value: object) -> object:
        return reject_non_integer(value, "value_minor_units")


class HoldingView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    holding_id: InvestmentHoldingId
    tenant_id: TenantId
    account_id: PersonalAccountId
    asset_class: AssetClass
    value_minor_units: int
    currency: Currency
    created_at: datetime


class AllocationRecommendationQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    risk_profile: RiskProfile
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _validate_window(self) -> "AllocationRecommendationQuery":
        require_aware_utc(self.start, "start")
        require_aware_utc(self.end, "end")
        if self.end <= self.start:
            raise ValueError("end must be after start")
        return self


class AllocationLineView(BaseModel):
    """One asset class's current-vs-target allocation (ADR-0023 §2 Fork 3: a
    deterministic fixed-target-weight comparison, not live market data or a
    trained model)."""

    model_config = ConfigDict(extra="forbid")

    asset_class: AssetClass
    current_value_minor_units: int
    # None iff total_portfolio_value_minor_units is 0 (never a divide-by-zero
    # placeholder — mirrors D-021's FinancialHealthView.savings_rate convention).
    current_pct: float | None
    target_pct: float
    # target_pct - current_pct; None whenever current_pct is None.
    drift_pct: float | None
    recommended_action: RebalanceAction
    recommended_rebalance_minor_units: int
    suggested_contribution_minor_units: int


class AllocationRecommendationView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    risk_profile: RiskProfile
    generated_at: datetime
    currency: Currency
    total_portfolio_value_minor_units: int
    lines: list[AllocationLineView]
    # Total suggested new contribution across all asset classes for the queried
    # window (sum of each line's suggested_contribution_minor_units).
    suggested_contribution_minor_units: int
    # A DETERMINISTIC fixed-target-weight heuristic, NOT machine learning / AI, NOT
    # live market pricing (mirrors D-021's health_score / D-011's forecasting
    # honesty convention — see service.py's module docstring for the formula).
    method: Literal["fixed_target_weights_v1"] = "fixed_target_weights_v1"
