"""Project-management persistence (D-015, ADR-0015).

Tenant-scoped reads/writes against ``sprints``/``tasks``/``task_dependencies``
(migration 0009). Every function takes an already-open :class:`AsyncSession` (from
``delta.persistence.database.get_tenant_session``) and does NOT commit — the caller
(``service.py``) owns the transaction, exactly like ``crm.store``/``erp.store``.

Velocity and bottleneck reports are bounded SQL aggregates (``SUM``/``COUNT`` with
``FILTER``/``GROUP BY``), never a per-task or per-edge Python loop over an unbounded
result set — the same O(1)-queries-per-request discipline D-011/D-012/D-013/D-014's
security reviews established.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import sprints, task_dependencies, tasks

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500

_MAX_DEPENDENCY_EDGES_CONSIDERED = 2000


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class SprintRecord:
    sprint_id: str
    tenant_id: str
    project_id: str
    name: str
    start_date: datetime
    end_date: datetime
    status: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class TaskRecord:
    task_id: str
    tenant_id: str
    project_id: str
    sprint_id: str | None
    title: str
    status: str
    story_points: int | None
    assignee: str | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None


@dataclass(frozen=True)
class TaskDependencyRecord:
    dependency_id: str
    tenant_id: str
    blocking_task_id: str
    blocked_task_id: str
    created_at: datetime


@dataclass(frozen=True)
class SprintVelocityRecord:
    sprint_id: str
    sprint_name: str
    status: str
    completed_story_points: int
    completed_task_count: int
    total_task_count: int


@dataclass(frozen=True)
class BottleneckRecord:
    task_id: str
    title: str
    status: str
    blocking_count: int


def _sprint_from_row(row) -> SprintRecord:
    return SprintRecord(
        sprint_id=row.sprint_id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        name=row.name,
        start_date=row.start_date,
        end_date=row.end_date,
        status=row.status,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _task_from_row(row) -> TaskRecord:
    return TaskRecord(
        task_id=row.task_id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        sprint_id=row.sprint_id,
        title=row.title,
        status=row.status,
        story_points=row.story_points,
        assignee=row.assignee,
        created_at=row.created_at,
        updated_at=row.updated_at,
        completed_at=row.completed_at,
    )


def _dependency_from_row(row) -> TaskDependencyRecord:
    return TaskDependencyRecord(
        dependency_id=row.dependency_id,
        tenant_id=row.tenant_id,
        blocking_task_id=row.blocking_task_id,
        blocked_task_id=row.blocked_task_id,
        created_at=row.created_at,
    )


# ------------------------------------------------------------------------- sprints


async def create_sprint(
    session: AsyncSession,
    *,
    tenant_id: str,
    project_id: str,
    name: str,
    start_date: datetime,
    end_date: datetime,
    now: datetime,
    sprint_id: str | None = None,
) -> SprintRecord:
    sid = sprint_id or str(uuid.uuid4())
    await session.execute(
        insert(sprints).values(
            sprint_id=sid,
            tenant_id=tenant_id,
            project_id=project_id,
            name=name,
            start_date=start_date,
            end_date=end_date,
            status="planned",
            created_at=now,
            updated_at=now,
        )
    )
    return SprintRecord(
        sprint_id=sid,
        tenant_id=tenant_id,
        project_id=project_id,
        name=name,
        start_date=start_date,
        end_date=end_date,
        status="planned",
        created_at=now,
        updated_at=now,
    )


async def get_sprint(session: AsyncSession, *, sprint_id: str) -> SprintRecord | None:
    row = (await session.execute(select(sprints).where(sprints.c.sprint_id == sprint_id))).first()
    return None if row is None else _sprint_from_row(row)


async def list_sprints(
    session: AsyncSession, *, project_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[SprintRecord]:
    stmt = (
        select(sprints)
        .where(sprints.c.project_id == project_id)
        .order_by(sprints.c.start_date.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_sprint_from_row(r) for r in rows]


async def update_sprint_status(
    session: AsyncSession, *, sprint_id: str, status: str, now: datetime
) -> None:
    await session.execute(
        update(sprints)
        .where(sprints.c.sprint_id == sprint_id)
        .values(status=status, updated_at=now)
    )


# ----------------------------------------------------------------------------- tasks


async def create_task(
    session: AsyncSession,
    *,
    tenant_id: str,
    project_id: str,
    sprint_id: str | None,
    title: str,
    story_points: int | None,
    assignee: str | None,
    now: datetime,
    task_id: str | None = None,
) -> TaskRecord:
    tid = task_id or str(uuid.uuid4())
    await session.execute(
        insert(tasks).values(
            task_id=tid,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=sprint_id,
            title=title,
            status="todo",
            story_points=story_points,
            assignee=assignee,
            created_at=now,
            updated_at=now,
            completed_at=None,
        )
    )
    return TaskRecord(
        task_id=tid,
        tenant_id=tenant_id,
        project_id=project_id,
        sprint_id=sprint_id,
        title=title,
        status="todo",
        story_points=story_points,
        assignee=assignee,
        created_at=now,
        updated_at=now,
        completed_at=None,
    )


async def get_task(session: AsyncSession, *, task_id: str) -> TaskRecord | None:
    row = (await session.execute(select(tasks).where(tasks.c.task_id == task_id))).first()
    return None if row is None else _task_from_row(row)


async def list_tasks(
    session: AsyncSession,
    *,
    project_id: str,
    sprint_id: str | None = None,
    status: str | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
) -> list[TaskRecord]:
    stmt = select(tasks).where(tasks.c.project_id == project_id)
    if sprint_id is not None:
        stmt = stmt.where(tasks.c.sprint_id == sprint_id)
    if status is not None:
        stmt = stmt.where(tasks.c.status == status)
    stmt = stmt.order_by(tasks.c.created_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_task_from_row(r) for r in rows]


async def update_task_status(
    session: AsyncSession, *, task_id: str, status: str, now: datetime
) -> None:
    completed_at = now if status == "done" else None
    await session.execute(
        update(tasks)
        .where(tasks.c.task_id == task_id)
        .values(status=status, updated_at=now, completed_at=completed_at)
    )


# ------------------------------------------------------------------ task_dependencies


async def create_dependency(
    session: AsyncSession,
    *,
    tenant_id: str,
    blocking_task_id: str,
    blocked_task_id: str,
    now: datetime,
    dependency_id: str | None = None,
) -> TaskDependencyRecord:
    did = dependency_id or str(uuid.uuid4())
    await session.execute(
        insert(task_dependencies).values(
            dependency_id=did,
            tenant_id=tenant_id,
            blocking_task_id=blocking_task_id,
            blocked_task_id=blocked_task_id,
            created_at=now,
        )
    )
    return TaskDependencyRecord(
        dependency_id=did,
        tenant_id=tenant_id,
        blocking_task_id=blocking_task_id,
        blocked_task_id=blocked_task_id,
        created_at=now,
    )


async def list_dependencies_for_task(
    session: AsyncSession, *, task_id: str
) -> list[TaskDependencyRecord]:
    stmt = select(task_dependencies).where(
        (task_dependencies.c.blocking_task_id == task_id)
        | (task_dependencies.c.blocked_task_id == task_id)
    )
    rows = (await session.execute(stmt)).all()
    return [_dependency_from_row(r) for r in rows]


async def list_all_dependency_edges(
    session: AsyncSession, *, limit: int = _MAX_DEPENDENCY_EDGES_CONSIDERED
) -> list[tuple[str, str]]:
    """Every ``(blocking_task_id, blocked_task_id)`` edge for the caller's tenant
    (RLS-confined), capped at ``limit`` (fetches ``limit + 1`` rows so the caller can
    detect truncation) — used only by the cycle-freedom check
    (``service._would_create_cycle``), never returned to a caller directly.

    Deliberately does NOT route through ``_clamp_limit``/``MAX_LIST_LIMIT`` — those
    bound pagination page sizes (500), which is unrelated to and smaller than the
    cycle-check's own edge budget (``_MAX_DEPENDENCY_EDGES_CONSIDERED`` = 2000); a
    security audit caught an earlier version silently routing through the pagination
    clamp, truncating the graph fed to the cycle check for any tenant with >500 edges.
    """
    fetch_limit = max(1, limit) + 1
    stmt = (
        select(task_dependencies.c.blocking_task_id, task_dependencies.c.blocked_task_id)
        .order_by(task_dependencies.c.created_at, task_dependencies.c.dependency_id)
        .limit(fetch_limit)
    )
    rows = (await session.execute(stmt)).all()
    return [(r.blocking_task_id, r.blocked_task_id) for r in rows]


# --------------------------------------------------------------------------- reports


async def get_velocity_report(
    session: AsyncSession, *, project_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[SprintVelocityRecord]:
    """One query: per-sprint completed story points / task counts via conditional
    aggregation, never one query per sprint."""
    stmt = (
        select(
            sprints.c.sprint_id,
            sprints.c.name,
            sprints.c.status,
            func.coalesce(func.sum(tasks.c.story_points).filter(tasks.c.status == "done"), 0),
            func.count(tasks.c.task_id).filter(tasks.c.status == "done"),
            func.count(tasks.c.task_id),
        )
        .select_from(sprints.outerjoin(tasks, tasks.c.sprint_id == sprints.c.sprint_id))
        .where(sprints.c.project_id == project_id)
        .group_by(sprints.c.sprint_id, sprints.c.name, sprints.c.status)
        .order_by(sprints.c.name)
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [
        SprintVelocityRecord(
            sprint_id=r[0],
            sprint_name=r[1],
            status=r[2],
            completed_story_points=int(r[3]),
            completed_task_count=r[4],
            total_task_count=r[5],
        )
        for r in rows
    ]


async def get_bottleneck_report(
    session: AsyncSession, *, project_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[BottleneckRecord]:
    """One query: non-done tasks ranked by how many OTHER tasks they block, via a
    LEFT JOIN + GROUP BY — never one query per task."""
    join_cond = task_dependencies.c.blocking_task_id == tasks.c.task_id
    stmt = (
        select(
            tasks.c.task_id,
            tasks.c.title,
            tasks.c.status,
            func.count(task_dependencies.c.dependency_id),
        )
        .select_from(tasks.outerjoin(task_dependencies, join_cond))
        .where(tasks.c.project_id == project_id)
        .where(tasks.c.status != "done")
        .group_by(tasks.c.task_id, tasks.c.title, tasks.c.status)
        .having(func.count(task_dependencies.c.dependency_id) > 0)
        .order_by(func.count(task_dependencies.c.dependency_id).desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [
        BottleneckRecord(task_id=r[0], title=r[1], status=r[2], blocking_count=r[3]) for r in rows
    ]
