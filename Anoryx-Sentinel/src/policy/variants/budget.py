"""BudgetLimitPolicy typed view + period bucketing helper (ADR-0009 §6, §10).

A budget policy carries token and/or cost ceilings per period (hourly/daily/
monthly) at a granularity selected by its own `scope` field (tenant/team/project/
agent). Unlike the model variants, budget policies do NOT use the wildcard
convention — the `scope` field selects which IDs are significant for matching.

HONEST LANGUAGE (CLAUDE.md): max_cost_cents_per_period is a client-side cost
ESTIMATE basis, never an authoritative bill.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

# period -> SQL date_trunc unit (semantics; the boundary is computed in Python so
# it is deterministically testable — see enforcement.budget_period_used).
PERIOD_TRUNC_UNIT: dict[str, str] = {"hourly": "hour", "daily": "day", "monthly": "month"}


class BudgetLimitPolicy(BaseModel):
    """Typed view of a validated budget_limit policy payload."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    policy_id: str
    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    policy_version: int
    period: Literal["hourly", "daily", "monthly"]
    scope: Literal["tenant", "team", "project", "agent"]
    max_tokens_per_period: int | None = None
    max_cost_cents_per_period: float | None = None

    @property
    def trunc_unit(self) -> str:
        return PERIOD_TRUNC_UNIT[self.period]
