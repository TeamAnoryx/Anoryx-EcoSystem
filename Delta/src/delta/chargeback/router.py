"""Chargeback/showback + anomaly HTTP surface (D-012):
``GET /v1/admin/chargeback/{report,anomalies}``. Reuses D-007's ``require_admin`` (same
admin console, same auth) — mounted into the shared admin app, not a second app/port
(mirrors D-008/D-009/D-011).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError

from ..allocation_admin.auth import require_admin
from ..identifiers import AgentId, ProjectId, TeamId, TenantId
from ..persistence.database import get_tenant_session
from .schemas import (
    AnomalyQuery,
    AnomalyReportView,
    ChargebackQuery,
    ChargebackReportView,
    GroupDimension,
)
from .service import get_anomaly_report, get_chargeback_report

router = APIRouter(prefix="/v1/admin/chargeback", dependencies=[Depends(require_admin)])


def _query_error(exc: ValidationError) -> HTTPException:
    return HTTPException(status_code=422, detail=str(exc))


@router.get("/report", response_model=ChargebackReportView)
async def report(
    tenant_id: TenantId,
    start: datetime,
    end: datetime,
    group_by: GroupDimension,
    team_id: TeamId | None = None,
    project_id: ProjectId | None = None,
    agent_id: AgentId | None = None,
) -> ChargebackReportView:
    try:
        query = ChargebackQuery(
            tenant_id=tenant_id,
            start=start,
            end=end,
            group_by=group_by,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
        )
    except ValidationError as exc:
        raise _query_error(exc) from exc
    async with get_tenant_session(tenant_id) as session:
        return await get_chargeback_report(session, query)


@router.get("/anomalies", response_model=AnomalyReportView)
async def anomalies(
    tenant_id: TenantId,
    start: datetime,
    end: datetime,
    group_by: GroupDimension,
    baseline_periods: int = 7,
    team_id: TeamId | None = None,
    project_id: ProjectId | None = None,
    agent_id: AgentId | None = None,
) -> AnomalyReportView:
    try:
        query = AnomalyQuery(
            tenant_id=tenant_id,
            start=start,
            end=end,
            group_by=group_by,
            baseline_periods=baseline_periods,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
        )
    except ValidationError as exc:
        raise _query_error(exc) from exc
    async with get_tenant_session(tenant_id) as session:
        return await get_anomaly_report(session, query)
