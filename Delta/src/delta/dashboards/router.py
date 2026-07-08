"""Dashboard HTTP surface: ``GET /v1/admin/dashboards/{summary,timeseries,top-spenders}``
(D-008). Reuses D-007's ``require_admin`` (same admin console, same auth) — mounted
into the shared admin app in ``allocation_admin/app.py``, not a second app/port.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError

from ..allocation_admin.auth import require_admin
from ..identifiers import AgentId, ProjectId, TeamId, TenantId
from ..persistence.database import get_tenant_session
from .schemas import (
    BucketGranularity,
    DashboardQuery,
    GroupDimension,
    GroupSpendView,
    SpendSummaryView,
    TimeSeriesPointView,
    TimeSeriesQuery,
    TopSpendersQuery,
)
from .service import get_summary, get_time_series, get_top_spenders

router = APIRouter(prefix="/v1/admin/dashboards", dependencies=[Depends(require_admin)])


def _query_error(exc: ValidationError) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


@router.get("/summary", response_model=SpendSummaryView)
async def summary(
    tenant_id: TenantId,
    start: datetime,
    end: datetime,
    team_id: TeamId | None = None,
    project_id: ProjectId | None = None,
    agent_id: AgentId | None = None,
) -> SpendSummaryView:
    try:
        query = DashboardQuery(
            tenant_id=tenant_id,
            start=start,
            end=end,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
        )
    except ValidationError as exc:
        raise _query_error(exc) from exc
    async with get_tenant_session(tenant_id) as session:
        return await get_summary(session, query)


@router.get("/timeseries", response_model=list[TimeSeriesPointView])
async def timeseries(
    tenant_id: TenantId,
    start: datetime,
    end: datetime,
    bucket: BucketGranularity = "day",
    team_id: TeamId | None = None,
    project_id: ProjectId | None = None,
    agent_id: AgentId | None = None,
) -> list[TimeSeriesPointView]:
    try:
        query = TimeSeriesQuery(
            tenant_id=tenant_id,
            start=start,
            end=end,
            bucket=bucket,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
        )
    except ValidationError as exc:
        raise _query_error(exc) from exc
    async with get_tenant_session(tenant_id) as session:
        return await get_time_series(session, query)


@router.get("/top-spenders", response_model=list[GroupSpendView])
async def top_spenders_route(
    tenant_id: TenantId,
    start: datetime,
    end: datetime,
    group_by: GroupDimension,
    limit: int = 10,
    team_id: TeamId | None = None,
    project_id: ProjectId | None = None,
    agent_id: AgentId | None = None,
) -> list[GroupSpendView]:
    try:
        query = TopSpendersQuery(
            tenant_id=tenant_id,
            start=start,
            end=end,
            group_by=group_by,
            limit=limit,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
        )
    except ValidationError as exc:
        raise _query_error(exc) from exc
    async with get_tenant_session(tenant_id) as session:
        return await get_top_spenders(session, query)
