"""Project-management orchestration (D-015, ADR-0015).

DTO <-> store mapping + the dependency-cycle check the database cannot express as a
constraint (Postgres has no native "no cycles in this edge table" CHECK). Mirrors
``crm.service``/``erp.service``: store functions never commit, this layer commits once
per mutating call.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from . import store
from .schemas import (
    BottleneckReportView,
    BottleneckRow,
    SprintCreateRequest,
    SprintStatusUpdateRequest,
    SprintVelocityRow,
    SprintView,
    TaskCreateRequest,
    TaskDependencyCreateRequest,
    TaskDependencyView,
    TaskStatusUpdateRequest,
    TaskView,
    VelocityReportView,
)


class SprintNotFoundError(LookupError):
    pass


class TaskNotFoundError(LookupError):
    pass


class SelfDependencyError(ValueError):
    """A task cannot block itself."""


class DependencyCycleError(ValueError):
    """Adding this edge would create a cycle in the dependency graph."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sprint_to_view(record: store.SprintRecord) -> SprintView:
    return SprintView(
        sprint_id=record.sprint_id,
        tenant_id=record.tenant_id,
        project_id=record.project_id,
        name=record.name,
        start_date=record.start_date,
        end_date=record.end_date,
        status=record.status,  # type: ignore[arg-type]
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _task_to_view(record: store.TaskRecord) -> TaskView:
    return TaskView(
        task_id=record.task_id,
        tenant_id=record.tenant_id,
        project_id=record.project_id,
        sprint_id=record.sprint_id,
        title=record.title,
        status=record.status,  # type: ignore[arg-type]
        story_points=record.story_points,
        assignee=record.assignee,
        created_at=record.created_at,
        updated_at=record.updated_at,
        completed_at=record.completed_at,
    )


def _dependency_to_view(record: store.TaskDependencyRecord) -> TaskDependencyView:
    return TaskDependencyView(
        dependency_id=record.dependency_id,
        tenant_id=record.tenant_id,
        blocking_task_id=record.blocking_task_id,
        blocked_task_id=record.blocked_task_id,
        created_at=record.created_at,
    )


def _would_create_cycle(
    edges: list[tuple[str, str]], *, new_blocking: str, new_blocked: str
) -> bool:
    """True iff adding ``new_blocking -> new_blocked`` closes a cycle — i.e.
    ``new_blocking`` is already reachable FROM ``new_blocked`` by following existing
    edges (``new_blocked`` already transitively blocks ``new_blocking``, so the new
    edge would require both to happen before the other)."""
    adjacency: dict[str, list[str]] = {}
    for blocking, blocked in edges:
        adjacency.setdefault(blocking, []).append(blocked)

    visited: set[str] = {new_blocked}
    queue: deque[str] = deque([new_blocked])
    while queue:
        node = queue.popleft()
        if node == new_blocking:
            return True
        for neighbor in adjacency.get(node, ()):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return False


# ------------------------------------------------------------------------- sprints


async def create_sprint(session: AsyncSession, req: SprintCreateRequest) -> SprintView:
    record = await store.create_sprint(
        session,
        tenant_id=req.tenant_id,
        project_id=req.project_id,
        name=req.name,
        start_date=req.start_date,
        end_date=req.end_date,
        now=_now(),
    )
    await session.commit()
    return _sprint_to_view(record)


async def list_sprint_views(
    session: AsyncSession, *, project_id: str, limit: int
) -> list[SprintView]:
    records = await store.list_sprints(session, project_id=project_id, limit=limit)
    return [_sprint_to_view(r) for r in records]


async def update_sprint_status(
    session: AsyncSession, *, sprint_id: str, req: SprintStatusUpdateRequest
) -> SprintView:
    existing = await store.get_sprint(session, sprint_id=sprint_id)
    if existing is None:
        raise SprintNotFoundError(sprint_id)
    now = _now()
    await store.update_sprint_status(session, sprint_id=sprint_id, status=req.status, now=now)
    record = await store.get_sprint(session, sprint_id=sprint_id)
    await session.commit()
    if record is None:
        raise SprintNotFoundError(sprint_id)  # unreachable: just wrote it in this transaction
    return _sprint_to_view(record)


# ----------------------------------------------------------------------------- tasks


async def create_task(session: AsyncSession, req: TaskCreateRequest) -> TaskView:
    if req.sprint_id is not None:
        sprint = await store.get_sprint(session, sprint_id=req.sprint_id)
        if sprint is None:
            raise SprintNotFoundError(req.sprint_id)
    record = await store.create_task(
        session,
        tenant_id=req.tenant_id,
        project_id=req.project_id,
        sprint_id=req.sprint_id,
        title=req.title,
        story_points=req.story_points,
        assignee=req.assignee,
        now=_now(),
    )
    await session.commit()
    return _task_to_view(record)


async def list_task_views(
    session: AsyncSession,
    *,
    project_id: str,
    sprint_id: str | None,
    status: str | None,
    limit: int,
) -> list[TaskView]:
    records = await store.list_tasks(
        session, project_id=project_id, sprint_id=sprint_id, status=status, limit=limit
    )
    return [_task_to_view(r) for r in records]


async def update_task_status(
    session: AsyncSession, *, task_id: str, req: TaskStatusUpdateRequest
) -> TaskView:
    existing = await store.get_task(session, task_id=task_id)
    if existing is None:
        raise TaskNotFoundError(task_id)
    now = _now()
    await store.update_task_status(session, task_id=task_id, status=req.status, now=now)
    record = await store.get_task(session, task_id=task_id)
    await session.commit()
    if record is None:
        raise TaskNotFoundError(task_id)  # unreachable: just wrote it in this transaction
    return _task_to_view(record)


# ------------------------------------------------------------------ task_dependencies


async def create_dependency(
    session: AsyncSession, req: TaskDependencyCreateRequest
) -> TaskDependencyView:
    if req.blocking_task_id == req.blocked_task_id:
        raise SelfDependencyError(req.blocking_task_id)

    blocking = await store.get_task(session, task_id=req.blocking_task_id)
    if blocking is None:
        raise TaskNotFoundError(req.blocking_task_id)
    blocked = await store.get_task(session, task_id=req.blocked_task_id)
    if blocked is None:
        raise TaskNotFoundError(req.blocked_task_id)

    edges = await store.list_all_dependency_edges(session)
    if _would_create_cycle(
        edges, new_blocking=req.blocking_task_id, new_blocked=req.blocked_task_id
    ):
        raise DependencyCycleError(
            f"{req.blocking_task_id} -> {req.blocked_task_id} would create a cycle"
        )

    record = await store.create_dependency(
        session,
        tenant_id=req.tenant_id,
        blocking_task_id=req.blocking_task_id,
        blocked_task_id=req.blocked_task_id,
        now=_now(),
    )
    await session.commit()
    return _dependency_to_view(record)


async def list_dependency_views_for_task(
    session: AsyncSession, *, task_id: str
) -> list[TaskDependencyView]:
    records = await store.list_dependencies_for_task(session, task_id=task_id)
    return [_dependency_to_view(r) for r in records]


# --------------------------------------------------------------------------- reports


async def get_velocity_report(
    session: AsyncSession, *, project_id: str, limit: int
) -> VelocityReportView:
    records = await store.get_velocity_report(session, project_id=project_id, limit=limit)
    return VelocityReportView(
        project_id=project_id,
        sprints=[
            SprintVelocityRow(
                sprint_id=r.sprint_id,
                sprint_name=r.sprint_name,
                status=r.status,  # type: ignore[arg-type]
                completed_story_points=r.completed_story_points,
                completed_task_count=r.completed_task_count,
                total_task_count=r.total_task_count,
            )
            for r in records
        ],
    )


async def get_bottleneck_report(
    session: AsyncSession, *, project_id: str, limit: int
) -> BottleneckReportView:
    records = await store.get_bottleneck_report(session, project_id=project_id, limit=limit)
    return BottleneckReportView(
        project_id=project_id,
        bottlenecks=[
            BottleneckRow(
                task_id=r.task_id,
                title=r.title,
                status=r.status,  # type: ignore[arg-type]
                blocking_count=r.blocking_count,
            )
            for r in records
        ],
    )
