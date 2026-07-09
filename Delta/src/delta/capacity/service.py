"""Team-capacity orchestration (D-016, ADR-0016).

DTO <-> store mapping + the greedy rebalance heuristic (a pure function, no DB —
mirrors ``pm.service._would_create_cycle``'s pure-traversal shape for the same
testability reason). Mirrors ``pm.service``: store functions never commit, this layer
commits once per mutating call.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from . import store
from .schemas import (
    RebalanceReportView,
    RebalanceSuggestion,
    TaskAssignmentView,
    TaskCapacityView,
    TaskTeamAssignRequest,
    TeamCapacityUpdateRequest,
    TeamCreateRequest,
    TeamView,
    UtilizationReportView,
    UtilizationRow,
)


class TeamNotFoundError(LookupError):
    pass


class TaskNotFoundError(LookupError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _team_to_view(record: store.TeamRecord) -> TeamView:
    return TeamView(
        team_id=record.team_id,
        tenant_id=record.tenant_id,
        name=record.name,
        capacity_points_per_sprint=record.capacity_points_per_sprint,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


# --------------------------------------------------------------------------- teams


async def create_team(session: AsyncSession, req: TeamCreateRequest) -> TeamView:
    record = await store.create_team(
        session,
        tenant_id=req.tenant_id,
        name=req.name,
        capacity_points_per_sprint=req.capacity_points_per_sprint,
        now=_now(),
    )
    await session.commit()
    return _team_to_view(record)


async def list_team_views(session: AsyncSession, *, limit: int) -> list[TeamView]:
    records = await store.list_teams(session, limit=limit)
    return [_team_to_view(r) for r in records]


async def update_team_capacity(
    session: AsyncSession, *, team_id: str, req: TeamCapacityUpdateRequest
) -> TeamView:
    existing = await store.get_team(session, team_id=team_id)
    if existing is None:
        raise TeamNotFoundError(team_id)
    now = _now()
    await store.update_team_capacity(
        session, team_id=team_id, capacity_points_per_sprint=req.capacity_points_per_sprint, now=now
    )
    record = await store.get_team(session, team_id=team_id)
    await session.commit()
    if record is None:
        raise TeamNotFoundError(team_id)  # unreachable: just wrote it in this transaction
    return _team_to_view(record)


# ----------------------------------------------------------------- task assignment


async def list_task_capacity_views(
    session: AsyncSession, *, project_id: str, sprint_id: str, limit: int
) -> list[TaskCapacityView]:
    records = await store.list_tasks_for_capacity(
        session, project_id=project_id, sprint_id=sprint_id, limit=limit
    )
    return [
        TaskCapacityView(
            task_id=r.task_id,
            title=r.title,
            status=r.status,
            story_points=r.story_points,
            team_id=r.team_id,
        )
        for r in records
    ]


async def assign_task_team(
    session: AsyncSession, *, task_id: str, req: TaskTeamAssignRequest
) -> TaskAssignmentView:
    task = await store.get_task_for_capacity(session, task_id=task_id)
    if task is None:
        raise TaskNotFoundError(task_id)
    if req.team_id is not None:
        team = await store.get_team(session, team_id=req.team_id)
        if team is None:
            raise TeamNotFoundError(req.team_id)
    await store.assign_task_team(session, task_id=task_id, team_id=req.team_id, now=_now())
    await session.commit()
    return TaskAssignmentView(task_id=task_id, tenant_id=req.tenant_id, team_id=req.team_id)


# --------------------------------------------------------------------------- reports


async def get_utilization_report(
    session: AsyncSession, *, project_id: str, sprint_id: str
) -> UtilizationReportView:
    records = await store.get_utilization_rows(session, project_id=project_id, sprint_id=sprint_id)
    rows = []
    for r in records:
        if r.capacity_points_per_sprint > 0:
            ratio: float | None = r.remaining_points / r.capacity_points_per_sprint
        elif r.remaining_points > 0:
            ratio = None  # undefined: nonzero load against zero declared capacity
        else:
            ratio = 0.0
        rows.append(
            UtilizationRow(
                team_id=r.team_id,
                team_name=r.team_name,
                capacity_points_per_sprint=r.capacity_points_per_sprint,
                total_assigned_points=r.total_assigned_points,
                remaining_points=r.remaining_points,
                utilization_ratio=ratio,
            )
        )
    return UtilizationReportView(project_id=project_id, sprint_id=sprint_id, teams=rows)


@dataclass(frozen=True)
class _TeamSnapshot:
    team_id: str
    name: str
    capacity: int
    remaining: int


@dataclass(frozen=True)
class _MovableTask:
    task_id: str
    title: str
    story_points: int
    team_id: str


@dataclass(frozen=True)
class _RebalanceMove:
    task_id: str
    title: str
    story_points: int
    from_team_id: str
    from_team_name: str
    to_team_id: str
    to_team_name: str


def _greedy_rebalance(
    teams_snapshot: list[_TeamSnapshot], movable_tasks: list[_MovableTask]
) -> list[_RebalanceMove]:
    """Deterministic first-fit-decreasing suggestion: move the largest not-done
    tasks from the most over-capacity teams to the team with the most spare
    capacity, until each over-capacity team's excess is cleared or it runs out of
    movable tasks. Never mutates anything — the caller only returns suggestions.

    Returns plain dataclasses (not the Pydantic ``RebalanceSuggestion`` DTO) so this
    stays a pure, dependency-free function directly unit-testable with arbitrary
    non-UUID-shaped ids — mirrors ``pm.service._would_create_cycle``'s pure-primitive
    shape. ``get_rebalance_report`` maps these to the wire DTO.
    """
    over = sorted(
        (t for t in teams_snapshot if t.remaining > t.capacity),
        key=lambda t: t.remaining - t.capacity,
        reverse=True,
    )
    under = [t for t in teams_snapshot if t.remaining < t.capacity]
    spare: dict[str, int] = {t.team_id: t.capacity - t.remaining for t in under}

    tasks_by_team: dict[str, list[_MovableTask]] = {}
    for task in movable_tasks:
        tasks_by_team.setdefault(task.team_id, []).append(task)
    for team_tasks in tasks_by_team.values():
        team_tasks.sort(key=lambda t: t.story_points, reverse=True)

    by_id = {t.team_id: t for t in teams_snapshot}
    moves: list[_RebalanceMove] = []

    for over_team in over:
        excess = over_team.remaining - over_team.capacity
        for task in tasks_by_team.get(over_team.team_id, []):
            if excess <= 0:
                break
            candidates = [team_id for team_id, s in spare.items() if s > 0]
            if not candidates:
                break
            target_id = max(candidates, key=lambda team_id: spare[team_id])
            moves.append(
                _RebalanceMove(
                    task_id=task.task_id,
                    title=task.title,
                    story_points=task.story_points,
                    from_team_id=over_team.team_id,
                    from_team_name=over_team.name,
                    to_team_id=target_id,
                    to_team_name=by_id[target_id].name,
                )
            )
            excess -= task.story_points
            spare[target_id] -= task.story_points

    return moves


async def get_rebalance_report(
    session: AsyncSession, *, project_id: str, sprint_id: str
) -> RebalanceReportView:
    utilization = await store.get_utilization_rows(
        session, project_id=project_id, sprint_id=sprint_id
    )
    movable = await store.list_movable_tasks(session, project_id=project_id, sprint_id=sprint_id)

    snapshots = [
        _TeamSnapshot(
            team_id=r.team_id,
            name=r.team_name,
            capacity=r.capacity_points_per_sprint,
            remaining=r.remaining_points,
        )
        for r in utilization
    ]
    movable_tasks = [
        _MovableTask(
            task_id=m.task_id, title=m.title, story_points=m.story_points, team_id=m.team_id
        )
        for m in movable
    ]
    moves = _greedy_rebalance(snapshots, movable_tasks)
    suggestions = [
        RebalanceSuggestion(
            task_id=m.task_id,
            title=m.title,
            story_points=m.story_points,
            from_team_id=m.from_team_id,
            from_team_name=m.from_team_name,
            to_team_id=m.to_team_id,
            to_team_name=m.to_team_name,
        )
        for m in moves
    ]
    return RebalanceReportView(project_id=project_id, sprint_id=sprint_id, suggestions=suggestions)
