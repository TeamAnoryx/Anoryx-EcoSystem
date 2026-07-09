"""Project-management HTTP surface: ``/v1/admin/pm/*`` (D-015).

Every route resolves a tenant-scoped session via ``get_tenant_session(tenant_id)`` —
the same "per-target session" shape D-007/D-008/D-011/D-012/D-013/D-014 all use.
``require_admin`` (imported from ``allocation_admin.auth``, not redefined here) gates
every route.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..allocation_admin.auth import require_admin
from ..identifiers import ProjectId, SprintId, TaskId, TenantId
from ..persistence.database import get_tenant_session
from . import service
from .schemas import DEFAULT_LIST_LIMIT as _DEFAULT_LIMIT
from .schemas import (
    BottleneckReportView,
    SprintCreateRequest,
    SprintStatusUpdateRequest,
    SprintView,
    TaskCreateRequest,
    TaskDependencyCreateRequest,
    TaskDependencyView,
    TaskStatus,
    TaskStatusUpdateRequest,
    TaskView,
    VelocityReportView,
)
from .service import (
    DependencyCycleError,
    SelfDependencyError,
    SprintNotFoundError,
    TaskNotFoundError,
    TooManyDependencyEdgesError,
)

router = APIRouter(prefix="/v1/admin/pm", dependencies=[Depends(require_admin)])


def _not_found(detail: str) -> HTTPException:
    return HTTPException(status_code=404, detail=detail)


# ------------------------------------------------------------------------- sprints


@router.post("/sprints", status_code=201, response_model=SprintView)
async def post_sprint(req: SprintCreateRequest) -> SprintView:
    async with get_tenant_session(req.tenant_id) as session:
        return await service.create_sprint(session, req)


@router.get("/sprints", response_model=list[SprintView])
async def get_sprints(
    tenant_id: TenantId, project_id: ProjectId, limit: int = _DEFAULT_LIMIT
) -> list[SprintView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_sprint_views(session, project_id=project_id, limit=limit)


@router.post("/sprints/{sprint_id}/status", response_model=SprintView)
async def post_sprint_status(sprint_id: SprintId, req: SprintStatusUpdateRequest) -> SprintView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.update_sprint_status(session, sprint_id=sprint_id, req=req)
        except SprintNotFoundError as exc:
            raise _not_found("sprint_not_found") from exc


# ----------------------------------------------------------------------------- tasks


@router.post("/tasks", status_code=201, response_model=TaskView)
async def post_task(req: TaskCreateRequest) -> TaskView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.create_task(session, req)
        except SprintNotFoundError as exc:
            raise _not_found("sprint_not_found") from exc


@router.get("/tasks", response_model=list[TaskView])
async def get_tasks(
    tenant_id: TenantId,
    project_id: ProjectId,
    sprint_id: SprintId | None = None,
    status: TaskStatus | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> list[TaskView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_task_views(
            session, project_id=project_id, sprint_id=sprint_id, status=status, limit=limit
        )


@router.post("/tasks/{task_id}/status", response_model=TaskView)
async def post_task_status(task_id: TaskId, req: TaskStatusUpdateRequest) -> TaskView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.update_task_status(session, task_id=task_id, req=req)
        except TaskNotFoundError as exc:
            raise _not_found("task_not_found") from exc


# ------------------------------------------------------------------ task_dependencies


@router.post("/dependencies", status_code=201, response_model=TaskDependencyView)
async def post_dependency(req: TaskDependencyCreateRequest) -> TaskDependencyView:
    async with get_tenant_session(req.tenant_id) as session:
        try:
            return await service.create_dependency(session, req)
        except TaskNotFoundError as exc:
            raise _not_found("task_not_found") from exc
        except SelfDependencyError as exc:
            raise HTTPException(status_code=422, detail="task_cannot_block_itself") from exc
        except DependencyCycleError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except TooManyDependencyEdgesError as exc:
            raise HTTPException(status_code=422, detail="too_many_dependency_edges") from exc


@router.get("/tasks/{task_id}/dependencies", response_model=list[TaskDependencyView])
async def get_task_dependencies(task_id: TaskId, tenant_id: TenantId) -> list[TaskDependencyView]:
    async with get_tenant_session(tenant_id) as session:
        return await service.list_dependency_views_for_task(session, task_id=task_id)


# --------------------------------------------------------------------------- reports


@router.get("/velocity", response_model=VelocityReportView)
async def get_velocity(
    tenant_id: TenantId, project_id: ProjectId, limit: int = _DEFAULT_LIMIT
) -> VelocityReportView:
    async with get_tenant_session(tenant_id) as session:
        return await service.get_velocity_report(session, project_id=project_id, limit=limit)


@router.get("/bottlenecks", response_model=BottleneckReportView)
async def get_bottlenecks(
    tenant_id: TenantId, project_id: ProjectId, limit: int = _DEFAULT_LIMIT
) -> BottleneckReportView:
    async with get_tenant_session(tenant_id) as session:
        return await service.get_bottleneck_report(session, project_id=project_id, limit=limit)
