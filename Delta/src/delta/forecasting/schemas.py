"""Forecast API response DTOs (D-011)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

Severity = Literal["info", "warning", "critical"]


class RecommendationView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    severity: Severity
    message: str


class BudgetForecastView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    budget_id: str
    tenant_id: str
    scope: str
    team_id: str
    project_id: str
    agent_id: str
    period: str
    currency: str
    cap_cost_cents: int | None
    period_start: datetime
    period_end: datetime
    current_period_spend_cents: int
    burn_rate_cents_per_hour: float
    # A float estimate, not integer cents — this is a projection, never fed back into
    # an actual enforcement decision (those stay strictly integer, budget_engine.decision).
    projected_period_end_spend_cents: float | None
    projected_exhaustion_at: datetime | None
    trend_direction: Literal["rising", "falling", "flat"] | None
    insufficient_data: bool
    # Explicit, honest method tag — a constant-rate projection from the ledger, not a
    # trained/validated model (ADR-0011 honesty boundary). Never rename silently; a
    # future different method should get a new literal value, not reuse this one.
    method: Literal["current_rate_projection_v1"] = "current_rate_projection_v1"
    recommendations: list[RecommendationView]
