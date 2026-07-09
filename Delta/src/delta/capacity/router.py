"""Team-capacity HTTP surface: ``/v1/admin/capacity/*`` (D-016).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)`` —
the same "per-target session" shape D-007/.../D-015 all use. ``require_admin``
(imported from ``allocation_admin.auth``, not redefined here) gates every route.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import ProjectId, SprintId, TaskId, TeamId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    RebalanceReportView,
    TaskAssignmentView,
    TaskCapacityView,
    TaskTeamAssignRequest,
    TeamCapacityUpdateRequest,
    TeamCreateRequest,
    TeamView,
    UtilizationReportView,
)
from .service import TaskNotFoundError, TeamNotFoundError

router = APIRouter(prefix="/v1/admin/capacity", dependencies=[Depends(require_admin)])


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


# ------------------------------------------------------------------------- teams


@router.post("/teams", status_code=201, response_model=TeamView)
async def post_team(req: TeamCreateRequest) -> TeamView:
    async with get_tenant_session(req.tenant_id) as session:
        return await service.create_team(session, req)


@router.get("/teams", response_model=list[TeamView])
async def get_teams(tenant_id: TenantId, limit: int = _DEFAULT_LIMIT) -> list[TeamView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_team_views(session, limit=limit)


@router.post("/teams/{team_id}/capacity", response_model=TeamView)
async def post_team_capacity(team_id: TeamId, req: TeamCapacityUpdateRequest) -> TeamView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.update_team_capacity(session, team_id=team_id, req=req)
        except TeamNotFoundError as exc:
            raise _not_found("team_not_found") from exc


# ----------------------------------------------------------------- task assignment


@router.get("/tasks", response_model=list[TaskCapacityView])
async def get_capacity_tasks(
    tenant_id: TenantId, project_id: ProjectId, sprint_id: SprintId, limit: int = _DEFAULT_LIMIT
) -> list[TaskCapacityView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_task_capacity_views(
            session, project_id=project_id, sprint_id=sprint_id, limit=limit
        )


@router.post("/tasks/{task_id}/team", response_model=TaskAssignmentView)
async def post_task_team(task_id: TaskId, req: TaskTeamAssignRequest) -> TaskAssignmentView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.assign_task_team(session, task_id=task_id, req=req)
        except TaskNotFoundError as exc:
            raise _not_found("task_not_found") from exc
        except TeamNotFoundError as exc:
            raise _not_found("team_not_found") from exc


# --------------------------------------------------------------------------- reports


@router.get("/utilization", response_model=UtilizationReportView)
async def get_utilization(
    tenant_id: TenantId, project_id: ProjectId, sprint_id: SprintId
) -> UtilizationReportView:
    async with get_tenant_session(tenant_id) as session:
        return await service.get_utilization_report(
            session, project_id=project_id, sprint_id=sprint_id
        )


@router.get("/rebalance", response_model=RebalanceReportView)
async def get_rebalance(
    tenant_id: TenantId, project_id: ProjectId, sprint_id: SprintId
) -> RebalanceReportView:
    async with get_tenant_session(tenant_id) as session:
        return await service.get_rebalance_report(
            session, project_id=project_id, sprint_id=sprint_id
        )
