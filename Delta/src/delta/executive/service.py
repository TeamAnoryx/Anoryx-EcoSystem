"""Executive dashboard orchestration (D-020, ADR-0020).

Composes D-008's spend summary and D-011's per-budget forecasts via their own SERVICE
functions (``dashboards.service.get_summary``, ``forecasting.service.
forecast_all_budgets``) rather than re-deriving burn-rate/forecast math against the
underlying tables — reusing already-computed, already-tested business logic is the
correct DRY boundary for a rollup whose entire purpose is composing OTHER modules'
outputs (ADR-0020 Fork 1). This is a deliberate departure from D-018/D-019's own
"query the shared table directly" convention, which applies to a simple existence/
amount check, not to reusing nontrivial aggregate computation. The D-013 CRM pipeline
rollup has no existing service-level aggregate to reuse, so it's a local read (see
``store.py``).

Read-only: no store function in this package writes anything, and this service never
calls ``session.commit()`` — there is nothing to commit (ADR-0020 §3).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from ..dashboards.schemas import DashboardQuery
from ..dashboards.service import get_summary
from ..forecasting.service import forecast_all_budgets
from ..money import DEFAULT_CURRENCY
from . import store
from .schemas import ExecutiveSummaryQuery, ExecutiveSummaryView

# forecast_all_budgets fans out several DB round-trips per budget — mirrors
# forecasting.router's own _MAX_LIST_FORECAST_BUDGETS cost-conscious cap rather than
# the higher generic definitions.list_budgets default (which the callee would silently
# clamp to anyway). `budgets_truncated` (below) is the honest signal for a tenant with
# more budgets than this cap (security audit finding, ADR-0020 §2 Fork 8).
_MAX_FORECAST_BUDGETS = 25


async def get_executive_summary(
    session: AsyncSession, query: ExecutiveSummaryQuery, *, now: datetime
) -> ExecutiveSummaryView:
    spend = await get_summary(
        session,
        DashboardQuery(
            tenant_id=query.tenant_id,
            start=query.start,
            end=query.end,
            team_id=None,
            project_id=None,
            agent_id=None,
        ),
    )

    forecasts = await forecast_all_budgets(session, now=now, limit=_MAX_FORECAST_BUDGETS)
    total_current_period_spend = sum(f.current_period_spend_cents for f in forecasts)
    projected_values = [
        f.projected_period_end_spend_cents
        for f in forecasts
        if f.projected_period_end_spend_cents is not None
    ]
    total_projected = sum(projected_values) if projected_values else None
    budgets_at_critical = sum(
        1 for f in forecasts if any(r.severity == "critical" for r in f.recommendations)
    )
    budgets_at_warning = sum(
        1
        for f in forecasts
        if any(r.severity == "warning" for r in f.recommendations)
        and not any(r.severity == "critical" for r in f.recommendations)
    )
    budgets_insufficient_data = sum(1 for f in forecasts if f.insufficient_data)

    pipeline = await store.get_pipeline_summary(session, currency=DEFAULT_CURRENCY)

    return ExecutiveSummaryView(
        tenant_id=query.tenant_id,
        period_start=query.start,
        period_end=query.end,
        generated_at=now,
        total_cost_cents=spend.total_cost_cents,
        request_count=spend.request_count,
        burn_rate_cents_per_hour=spend.burn_rate_cents_per_hour,
        budget_count=len(forecasts),
        budgets_truncated=len(forecasts) >= _MAX_FORECAST_BUDGETS,
        total_current_period_spend_cents=total_current_period_spend,
        total_projected_period_end_spend_cents=total_projected,
        budgets_at_critical=budgets_at_critical,
        budgets_at_warning=budgets_at_warning,
        budgets_insufficient_data=budgets_insufficient_data,
        client_count=pipeline.client_count,
        open_deal_count=pipeline.open_deal_count,
        open_pipeline_value_minor_units=pipeline.open_pipeline_value_minor_units,
        pipeline_currency=DEFAULT_CURRENCY,
    )
