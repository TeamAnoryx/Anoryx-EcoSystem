"""Forecast HTTP surface: ``GET /v1/admin/forecast/budgets[/{budget_id}]`` (D-011).
Reuses D-007's ``require_admin`` (same admin console, same auth) — mounted into the
shared admin app, not a second app/port (mirrors D-008/D-009).
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import TenantId, UuidStr
from ..persistence.database import get_tenant_session
from .schemas import BudgetForecastView
from .service import forecast_all_budgets, forecast_budget

router = APIRouter(prefix="/v1/admin/forecast", dependencies=[Depends(require_admin)])

# forecast_all_budgets fans out up to ~4 DB round-trips per budget (current spend, two
# half-window spends, top_spenders) — a smaller cap than the general-purpose
# definitions.list_budgets default (100) keeps a single request's worst-case query count
# in the same ballpark as D-008's own list endpoints (independent security review).
_MAX_LIST_FORECAST_BUDGETS = 25


def _now() -> datetime:
    return datetime.now(timezone.utc)


@router.get("/budgets", response_model=list[BudgetForecastView])
async def list_forecasts(tenant_id: TenantId) -> list[BudgetForecastView]:
    async with get_tenant_session(tenant_id) as session:
        return await forecast_all_budgets(session, now=_now(), limit=_MAX_LIST_FORECAST_BUDGETS)


@router.get("/budgets/{budget_id}", response_model=BudgetForecastView)
async def get_forecast(tenant_id: TenantId, budget_id: UuidStr) -> BudgetForecastView:
    async with get_tenant_session(tenant_id) as session:
        result = await forecast_budget(session, budget_id=budget_id, now=_now())
    if result is None:
        raise HTTPException(status_code=404, detail="budget_not_found")
    return result
