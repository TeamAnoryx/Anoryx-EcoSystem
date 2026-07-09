"""D-016 non-stubbed capacity persistence suite: real store writes -> real SQL reads,
real RLS. Mirrors ``tests/pm/test_store_db.py``'s shape. Tasks are created via
``delta.pm.store`` (D-016 never modifies ``delta.pm``) and then assigned to a team
via ``delta.capacity.store.assign_task_team``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from delta.capacity import store
from delta.persistence.database import get_tenant_session
from delta.pm import store as pm_store

from .conftest import db_required

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_SPRINT_END = _NOW + timedelta(days=14)


async def _make_task(
    session, *, tenant_id, project_id, sprint_id, title, story_points, status="todo"
):
    task = await pm_store.create_task(
        session,
        tenant_id=tenant_id,
        project_id=project_id,
        sprint_id=sprint_id,
        title=title,
        story_points=story_points,
        assignee=None,
        now=_NOW,
    )
    if status != "todo":
        await pm_store.update_task_status(session, task_id=task.task_id, status=status, now=_NOW)
    return task


@db_required
async def test_create_and_get_team_roundtrip(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_team(
            session,
            tenant_id=tenant_id,
            name="Platform Squad",
            capacity_points_per_sprint=20,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_team(session, team_id=created.team_id)

    assert fetched is not None
    assert fetched.name == "Platform Squad"
    assert fetched.capacity_points_per_sprint == 20


@db_required
async def test_update_team_capacity_persists(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        team = await store.create_team(
            session, tenant_id=tenant_id, name="Squad", capacity_points_per_sprint=10, now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        await store.update_team_capacity(
            session, team_id=team.team_id, capacity_points_per_sprint=25, now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        updated = await store.get_team(session, team_id=team.team_id)
    assert updated is not None
    assert updated.capacity_points_per_sprint == 25


@db_required
async def test_assign_task_team_and_unassign_roundtrip(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        team = await store.create_team(
            session, tenant_id=tenant_id, name="Squad", capacity_points_per_sprint=10, now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        task = await _make_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=None,
            title="Build widget",
            story_points=3,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        await store.assign_task_team(session, task_id=task.task_id, team_id=team.team_id, now=_NOW)
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_task_for_capacity(session, task_id=task.task_id)
    assert fetched is not None
    assert fetched.team_id == team.team_id

    async with get_tenant_session(tenant_id) as session:
        await store.assign_task_team(session, task_id=task.task_id, team_id=None, now=_NOW)
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        unassigned = await store.get_task_for_capacity(session, task_id=task.task_id)
    assert unassigned is not None
    assert unassigned.team_id is None


@db_required
async def test_list_tasks_for_capacity_reflects_team_assignment(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        sprint = await pm_store.create_sprint(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            name="Sprint 1",
            start_date=_NOW,
            end_date=_SPRINT_END,
            now=_NOW,
        )
        team = await store.create_team(
            session, tenant_id=tenant_id, name="Squad", capacity_points_per_sprint=10, now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        task = await _make_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=sprint.sprint_id,
            title="Build widget",
            story_points=3,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        before = await store.list_tasks_for_capacity(
            session, project_id=project_id, sprint_id=sprint.sprint_id
        )
    assert [t.team_id for t in before] == [None]

    async with get_tenant_session(tenant_id) as session:
        await store.assign_task_team(session, task_id=task.task_id, team_id=team.team_id, now=_NOW)
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        after = await store.list_tasks_for_capacity(
            session, project_id=project_id, sprint_id=sprint.sprint_id
        )
    assert [t.team_id for t in after] == [team.team_id]


@db_required
async def test_utilization_rows_computes_totals_and_excludes_done_from_remaining(
    tenant_id, project_id
) -> None:
    async with get_tenant_session(tenant_id) as session:
        sprint = await pm_store.create_sprint(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            name="Sprint 1",
            start_date=_NOW,
            end_date=_SPRINT_END,
            now=_NOW,
        )
        team_with_work = await store.create_team(
            session, tenant_id=tenant_id, name="Busy Squad", capacity_points_per_sprint=10, now=_NOW
        )
        idle_team = await store.create_team(
            session, tenant_id=tenant_id, name="Idle Squad", capacity_points_per_sprint=10, now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        done_task = await _make_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=sprint.sprint_id,
            title="Done task",
            story_points=5,
        )
        todo_task = await _make_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=sprint.sprint_id,
            title="Todo task",
            story_points=8,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        await store.assign_task_team(
            session, task_id=done_task.task_id, team_id=team_with_work.team_id, now=_NOW
        )
        await store.assign_task_team(
            session, task_id=todo_task.task_id, team_id=team_with_work.team_id, now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        await pm_store.update_task_status(
            session, task_id=done_task.task_id, status="done", now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        rows = await store.get_utilization_rows(
            session, project_id=project_id, sprint_id=sprint.sprint_id
        )

    by_id = {r.team_id: r for r in rows}
    busy = by_id[team_with_work.team_id]
    idle = by_id[idle_team.team_id]

    # total_assigned counts BOTH tasks (5 + 8 = 13); remaining excludes the done one
    # (only the 8-point todo task still counts against capacity).
    assert busy.total_assigned_points == 13
    assert busy.remaining_points == 8
    # The idle team has no tasks this sprint but still appears (LEFT JOIN), 0/0.
    assert idle.total_assigned_points == 0
    assert idle.remaining_points == 0


@db_required
async def test_list_movable_tasks_excludes_done_unassigned_and_unsized(
    tenant_id, project_id
) -> None:
    async with get_tenant_session(tenant_id) as session:
        sprint = await pm_store.create_sprint(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            name="Sprint 1",
            start_date=_NOW,
            end_date=_SPRINT_END,
            now=_NOW,
        )
        team = await store.create_team(
            session, tenant_id=tenant_id, name="Squad", capacity_points_per_sprint=10, now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        movable = await _make_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=sprint.sprint_id,
            title="Movable",
            story_points=5,
        )
        done = await _make_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=sprint.sprint_id,
            title="Done",
            story_points=5,
            status="done",
        )
        unsized = await _make_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=sprint.sprint_id,
            title="Unsized",
            story_points=None,
        )
        # Deliberately left with no team assignment below — proves
        # `list_movable_tasks` excludes team-less tasks entirely.
        await _make_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=sprint.sprint_id,
            title="Unassigned",
            story_points=5,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        for t in (movable, done, unsized):
            await store.assign_task_team(session, task_id=t.task_id, team_id=team.team_id, now=_NOW)
        # `unassigned` deliberately left with no team.
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        rows = await store.list_movable_tasks(
            session, project_id=project_id, sprint_id=sprint.sprint_id
        )

    assert [r.task_id for r in rows] == [movable.task_id]


@db_required
async def test_cross_tenant_isolation_teams_invisible_to_other_tenant(
    tenant_id, other_tenant_id
) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_team(
            session, tenant_id=tenant_id, name="Squad", capacity_points_per_sprint=10, now=_NOW
        )
        await session.commit()

    async with get_tenant_session(other_tenant_id) as session:
        fetched = await store.get_team(session, team_id=created.team_id)
        listed = await store.list_teams(session)

    assert fetched is None
    assert listed == []
