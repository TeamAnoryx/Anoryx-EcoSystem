"""Budget concept — the Delta-side shape that maps 1:1 onto Sentinel's LOCKED
``BudgetLimitPolicy`` (Fork 1a + the CONFIRM).

A ``BudgetConcept`` carries token and/or cost ceilings per period at a scope. Its
fields and bounds mirror the locked ``budget_limit`` variant so D-002 can serialize
it with no schema change (see :mod:`delta.attribution` for the builder and the
round-trip test). Cost is integer cents (Fork 2); the at-least-one-of rule mirrors
the schema's ``anyOf`` (a budget that limits nothing is rejected).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from .identifiers import AgentId, ProjectId, TeamId, TenantId
from .money import (
    DEFAULT_CURRENCY,
    MAX_BUDGET_COST_CENTS,
    MAX_BUDGET_TOKENS,
    Currency,
    bounded_count,
)


class BudgetScope(StrEnum):
    TENANT = "tenant"
    TEAM = "team"
    PROJECT = "project"
    AGENT = "agent"


class BudgetPeriod(StrEnum):
    HOURLY = "hourly"
    DAILY = "daily"
    MONTHLY = "monthly"


class BudgetConcept(BaseModel):
    """Token/cost ceiling per period at a scope. Serializes to a ``budget_limit``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: TenantId
    team_id: TeamId
    project_id: ProjectId
    agent_id: AgentId
    scope: BudgetScope
    period: BudgetPeriod
    limit_tokens: int | None = None
    limit_cost_cents: int | None = None
    currency: Currency = DEFAULT_CURRENCY

    @field_validator("limit_tokens", mode="before")
    @classmethod
    def _tokens(cls, value: object) -> object:
        return None if value is None else bounded_count(value, "limit_tokens", MAX_BUDGET_TOKENS)

    @field_validator("limit_cost_cents", mode="before")
    @classmethod
    def _cost(cls, value: object) -> object:
        if value is None:
            return None
        return bounded_count(value, "limit_cost_cents", MAX_BUDGET_COST_CENTS)

    @model_validator(mode="after")
    def _at_least_one_limit(self) -> "BudgetConcept":
        # Mirrors the schema's anyOf: a budget that limits neither tokens nor cost is invalid.
        if self.limit_tokens is None and self.limit_cost_cents is None:
            raise ValueError("budget must set at least one of limit_tokens or limit_cost_cents")
        return self
