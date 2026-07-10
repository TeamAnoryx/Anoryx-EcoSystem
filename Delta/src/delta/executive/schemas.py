"""Executive financial dashboard API request/response DTOs (D-020, ADR-0020).

A deliberately bounded vertical slice: a single READ-ONLY rollup composing D-008's
spend summary, D-011's per-budget forecasts, and D-013's CRM pipeline into one view —
"top-level executive financial view across the OS," scoped to exactly the three
tasks the roadmap itself names as dependencies (D-008, D-011, D-013), not literally
every Delta module. No new tables; no write path at all (ADR-0020 §3).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, model_validator

from ..identifiers import TenantId
from ..money import Currency, require_aware_utc


class ExecutiveSummaryQuery(BaseModel):
    """Shared window parameters — mirrors D-008's `DashboardQuery`, always tenant-wide
    (no team/project/agent scope: an executive rollup is deliberately not sliced)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _validate_window(self) -> "ExecutiveSummaryQuery":
        require_aware_utc(self.start, "start")
        require_aware_utc(self.end, "end")
        if self.end <= self.start:
            raise ValueError("end must be after start")
        return self


class ExecutiveSummaryView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    period_start: datetime
    period_end: datetime
    generated_at: datetime

    # D-008 — current-window spend.
    total_cost_cents: int
    request_count: int
    burn_rate_cents_per_hour: float

    # D-011 — per-budget forecast rollup. `total_projected_period_end_spend_cents` is
    # `None` iff every budget has `insufficient_data` (mirrors the per-budget field's
    # own honesty convention — never silently substituted with 0).
    budget_count: int
    total_current_period_spend_cents: int
    total_projected_period_end_spend_cents: float | None
    budgets_at_critical: int
    budgets_at_warning: int
    budgets_insufficient_data: int

    # D-013 — open CRM pipeline (deals not yet 'won'/'lost').
    client_count: int
    open_deal_count: int
    open_pipeline_value_minor_units: int
    pipeline_currency: Currency
