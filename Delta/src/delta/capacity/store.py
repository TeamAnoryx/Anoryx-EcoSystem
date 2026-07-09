"""Team-capacity persistence (D-016, ADR-0016).

Tenant-scoped reads/writes against ``teams`` and the additive ``tasks.team_id``
column (migration 0010). Every function takes an already-open :class:`AsyncSession`
(from ``delta.persistence.database.get_tenant_session``) and does NOT commit — the
caller (``service.py``) owns the transaction, exactly like ``pm.store``.

The utilization report is a single bounded SQL aggregate (``SUM`` with ``FILTER``,
``GROUP BY``), never a per-team Python loop — same O(1)-queries-per-request
discipline D-011/D-012/D-013/D-014/D-015's security reviews established. The
rebalance report's movable-task lookup is a single query scoped to one
project+sprint (inherently small), never a per-team query.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import tasks, teams

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500

_MAX_MOVABLE_TASKS_CONSIDERED = 1000


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


@dataclass(frozen=True)
class TeamRecord:
    team_id: str
    tenant_id: str
    name: str
    capacity_points_per_sprint: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class TaskCapacityRecord:
    task_id: str
    tenant_id: str
    project_id: str
    sprint_id: str | None
    title: str
    status: str
    story_points: int | None
    team_id: str | None


@dataclass(frozen=True)
class UtilizationRecord:
    team_id: str
    team_name: str
    capacity_points_per_sprint: int
    total_assigned_points: int
    remaining_points: int


@dataclass(frozen=True)
class MovableTaskRecord:
    task_id: str
    title: str
    story_points: int
    team_id: str


def _team_from_row(row) -> TeamRecord:
    return TeamRecord(
        team_id=row.team_id,
        tenant_id=row.tenant_id,
        name=row.name,
        capacity_points_per_sprint=row.capacity_points_per_sprint,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


# --------------------------------------------------------------------------- teams


async def create_team(
    session: AsyncSession,
    *,
    tenant_id: str,
    name: str,
    capacity_points_per_sprint: int,
    now: datetime,
    team_id: str | None = None,
) -> TeamRecord:
    tid = team_id or str(uuid.uuid4())
    await session.execute(
        insert(teams).values(
            team_id=tid,
            tenant_id=tenant_id,
            name=name,
            capacity_points_per_sprint=capacity_points_per_sprint,
            created_at=now,
            updated_at=now,
        )
    )
    return TeamRecord(
        team_id=tid,
        tenant_id=tenant_id,
        name=name,
        capacity_points_per_sprint=capacity_points_per_sprint,
        created_at=now,
        updated_at=now,
    )


async def get_team(session: AsyncSession, *, team_id: str) -> TeamRecord | None:
    row = (await session.execute(select(teams).where(teams.c.team_id == team_id))).first()
    return None if row is None else _team_from_row(row)


async def list_teams(session: AsyncSession, *, limit: int = DEFAULT_LIST_LIMIT) -> list[TeamRecord]:
    stmt = select(teams).order_by(teams.c.name).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_team_from_row(r) for r in rows]


async def update_team_capacity(
    session: AsyncSession, *, team_id: str, capacity_points_per_sprint: int, now: datetime
) -> None:
    await session.execute(
        update(teams)
        .where(teams.c.team_id == team_id)
        .values(capacity_points_per_sprint=capacity_points_per_sprint, updated_at=now)
    )


# ----------------------------------------------------------------- task assignment


async def get_task_for_capacity(
    session: AsyncSession, *, task_id: str
) -> TaskCapacityRecord | None:
    stmt = select(
        tasks.c.task_id,
        tasks.c.tenant_id,
        tasks.c.project_id,
        tasks.c.sprint_id,
        tasks.c.title,
        tasks.c.status,
        tasks.c.story_points,
        tasks.c.team_id,
    ).where(tasks.c.task_id == task_id)
    row = (await session.execute(stmt)).first()
    if row is None:
        return None
    return TaskCapacityRecord(
        task_id=row.task_id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        sprint_id=row.sprint_id,
        title=row.title,
        status=row.status,
        story_points=row.story_points,
        team_id=row.team_id,
    )


async def list_tasks_for_capacity(
    session: AsyncSession, *, project_id: str, sprint_id: str, limit: int = DEFAULT_LIST_LIMIT
) -> list[TaskCapacityRecord]:
    """Every task in one sprint with its current team assignment — `delta.pm.store`
    intentionally never reads/writes `team_id`, so the capacity UI reads task rows
    through here instead of `pm.list_tasks` whenever it needs `team_id`."""
    stmt = (
        select(
            tasks.c.task_id,
            tasks.c.tenant_id,
            tasks.c.project_id,
            tasks.c.sprint_id,
            tasks.c.title,
            tasks.c.status,
            tasks.c.story_points,
            tasks.c.team_id,
        )
        .where(tasks.c.project_id == project_id)
        .where(tasks.c.sprint_id == sprint_id)
        .order_by(tasks.c.created_at.desc())
        .limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [
        TaskCapacityRecord(
            task_id=r.task_id,
            tenant_id=r.tenant_id,
            project_id=r.project_id,
            sprint_id=r.sprint_id,
            title=r.title,
            status=r.status,
            story_points=r.story_points,
            team_id=r.team_id,
        )
        for r in rows
    ]


async def assign_task_team(
    session: AsyncSession, *, task_id: str, team_id: str | None, now: datetime
) -> None:
    await session.execute(
        update(tasks).where(tasks.c.task_id == task_id).values(team_id=team_id, updated_at=now)
    )


# --------------------------------------------------------------------------- reports


async def get_utilization_rows(
    session: AsyncSession, *, project_id: str, sprint_id: str
) -> list[UtilizationRecord]:
    """One query: per-team total/remaining assigned story points for one sprint via
    an outer join + conditional aggregation — never one query per team. Teams with no
    tasks assigned this sprint still appear (0 assigned, 0 remaining) via the LEFT
    JOIN, surfacing idle capacity."""
    join_cond = (
        (tasks.c.team_id == teams.c.team_id)
        & (tasks.c.project_id == project_id)
        & (tasks.c.sprint_id == sprint_id)
    )
    stmt = (
        select(
            teams.c.team_id,
            teams.c.name,
            teams.c.capacity_points_per_sprint,
            func.coalesce(func.sum(tasks.c.story_points), 0),
            func.coalesce(func.sum(tasks.c.story_points).filter(tasks.c.status != "done"), 0),
        )
        .select_from(teams.outerjoin(tasks, join_cond))
        .group_by(teams.c.team_id, teams.c.name, teams.c.capacity_points_per_sprint)
        .order_by(teams.c.name)
    )
    rows = (await session.execute(stmt)).all()
    return [
        UtilizationRecord(
            team_id=r[0],
            team_name=r[1],
            capacity_points_per_sprint=r[2],
            total_assigned_points=int(r[3]),
            remaining_points=int(r[4]),
        )
        for r in rows
    ]


async def list_movable_tasks(
    session: AsyncSession,
    *,
    project_id: str,
    sprint_id: str,
    limit: int = _MAX_MOVABLE_TASKS_CONSIDERED,
) -> list[MovableTaskRecord]:
    """Every not-done, sized, team-assigned task for one sprint (bounded), ordered by
    team then story points descending — used only by the rebalance suggestion
    (``service._greedy_rebalance``), never returned to a caller directly."""
    stmt = (
        select(tasks.c.task_id, tasks.c.title, tasks.c.story_points, tasks.c.team_id)
        .where(tasks.c.project_id == project_id)
        .where(tasks.c.sprint_id == sprint_id)
        .where(tasks.c.status != "done")
        .where(tasks.c.team_id.isnot(None))
        .where(tasks.c.story_points.isnot(None))
        .where(tasks.c.story_points > 0)
        .order_by(tasks.c.team_id, tasks.c.story_points.desc())
        .limit(max(1, limit))
    )
    rows = (await session.execute(stmt)).all()
    return [
        MovableTaskRecord(task_id=r[0], title=r[1], story_points=r[2], team_id=r[3]) for r in rows
    ]
