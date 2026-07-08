"""Forecast orchestration (D-011): budget lookup -> spend queries -> projection -> view.

Every spend figure comes from :mod:`budget_engine.spend` (``scope_spend_cents`` — the
SAME authoritative net-expense-balance query the budget engine itself uses for
enforcement, ADR-0005 §3.1), not a re-derivation — a forecast can never disagree with
enforcement about "how much has been spent so far" because it asks the identical question.
The "where to look" recommendation reuses D-008's ``dashboards.store.top_spenders``
unchanged.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from ..budget import BudgetScope
from ..budget_engine import definitions, periods, spend
from ..budget_engine.definitions import BudgetDefinition
from ..dashboards import store as dashboards_store
from .projection import compute_projection, exhaustion_at
from .recommendations import build_recommendations
from .schemas import BudgetForecastView, RecommendationView

# group_by dimension for the "where to look" concentration check, one level finer than
# the budget's own scope. An AGENT-scoped budget is already the finest granularity Delta
# tracks, so it has no concentration breakdown to offer.
_CONCENTRATION_GROUP_BY: dict[BudgetScope, str] = {
    BudgetScope.TENANT: "team_id",
    BudgetScope.TEAM: "agent_id",
    BudgetScope.PROJECT: "agent_id",
}


def _scope_filter_for(budget: BudgetDefinition) -> dashboards_store.ScopeFilter:
    if budget.scope is BudgetScope.TEAM:
        return dashboards_store.ScopeFilter(team_id=budget.team_id)
    if budget.scope is BudgetScope.PROJECT:
        return dashboards_store.ScopeFilter(project_id=budget.project_id)
    if budget.scope is BudgetScope.AGENT:
        return dashboards_store.ScopeFilter(agent_id=budget.agent_id)
    return dashboards_store.ScopeFilter()  # TENANT: no sub-id filter


async def _period_spend(
    session: AsyncSession, *, budget: BudgetDefinition, start: datetime, end: datetime
) -> int:
    return await spend.scope_spend_cents(
        session,
        scope=budget.scope,
        tenant_id=budget.tenant_id,
        team_id=budget.team_id,
        project_id=budget.project_id,
        agent_id=budget.agent_id,
        currency=budget.currency,
        period_start=start,
        period_end=end,
    )


async def _forecast_for(
    session: AsyncSession, *, budget: BudgetDefinition, now: datetime
) -> BudgetForecastView:
    period_start = periods.period_start(budget.period, now)
    period_end = periods.period_end(budget.period, now)

    current_spend = await _period_spend(session, budget=budget, start=period_start, end=now)

    elapsed_hours = (now - period_start).total_seconds() / 3600.0
    first_half_spend = 0
    second_half_spend = 0
    # Only worth two extra queries once each half would itself clear the minimum
    # elapsed-time bar a projection needs — otherwise the halves are noise anyway.
    if elapsed_hours >= 2.0:
        midpoint = period_start + (now - period_start) / 2
        first_half_spend = await _period_spend(
            session, budget=budget, start=period_start, end=midpoint
        )
        second_half_spend = await _period_spend(session, budget=budget, start=midpoint, end=now)

    projection = compute_projection(
        period_start=period_start,
        period_end=period_end,
        now=now,
        current_period_spend_cents=current_spend,
        first_half_spend_cents=first_half_spend,
        second_half_spend_cents=second_half_spend,
    )

    top_spender = None
    group_by = _CONCENTRATION_GROUP_BY.get(budget.scope)
    if group_by is not None:
        rows = await dashboards_store.top_spenders(
            session,
            start=period_start,
            end=now,
            group_by=group_by,  # type: ignore[arg-type]
            scope=_scope_filter_for(budget),
            limit=1,
        )
        top_spender = rows[0] if rows else None

    exhaustion = None
    if (
        not projection.insufficient_data
        and budget.limit_cost_cents is not None
        and projection.projected_period_end_spend_cents is not None
        and projection.projected_period_end_spend_cents > budget.limit_cost_cents
    ):
        exhaustion = exhaustion_at(
            now=now,
            period_end=period_end,
            current_period_spend_cents=current_spend,
            cap_cost_cents=budget.limit_cost_cents,
            burn_rate_cents_per_hour=projection.burn_rate_cents_per_hour,
        )

    recs = build_recommendations(
        budget=budget, projection=projection, top_spender=top_spender, exhaustion_at=exhaustion
    )

    return BudgetForecastView(
        budget_id=budget.budget_id,
        tenant_id=budget.tenant_id,
        scope=budget.scope.value,
        team_id=budget.team_id,
        project_id=budget.project_id,
        agent_id=budget.agent_id,
        period=budget.period.value,
        currency=budget.currency,
        cap_cost_cents=budget.limit_cost_cents,
        period_start=period_start,
        period_end=period_end,
        current_period_spend_cents=current_spend,
        burn_rate_cents_per_hour=projection.burn_rate_cents_per_hour,
        projected_period_end_spend_cents=projection.projected_period_end_spend_cents,
        projected_exhaustion_at=exhaustion,
        trend_direction=projection.trend_direction,
        insufficient_data=projection.insufficient_data,
        recommendations=[
            RecommendationView(code=r.code, severity=r.severity, message=r.message) for r in recs
        ],
    )


async def forecast_budget(
    session: AsyncSession, *, budget_id: str, now: datetime
) -> BudgetForecastView | None:
    """Forecast one budget by id. ``None`` when it doesn't exist (or isn't this tenant's,
    RLS-indistinguishable by design — mirrors ``definitions.get_budget``)."""
    budget = await definitions.get_budget(session, budget_id=budget_id)
    if budget is None:
        return None
    return await _forecast_for(session, budget=budget, now=now)


async def forecast_all_budgets(
    session: AsyncSession, *, now: datetime, limit: int = 100
) -> list[BudgetForecastView]:
    """Forecast every one of the caller's tenant's budgets (RLS-confined), capped."""
    budgets = await definitions.list_budgets(session, limit=limit)
    return [await _forecast_for(session, budget=b, now=now) for b in budgets]
