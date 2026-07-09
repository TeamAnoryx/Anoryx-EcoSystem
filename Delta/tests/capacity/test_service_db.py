"""D-016 service-layer DB tests: exception mapping + the utilization/rebalance
reports against a real graph (delta.capacity.service).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from delta.capacity import store as capacity_store
from delta.capacity.schemas import (
    TaskTeamAssignRequest,
    TeamCapacityUpdateRequest,
    TeamCreateRequest,
)
from delta.capacity.service import (
    TaskNotFoundError,
    TeamNotFoundError,
    assign_task_team,
    create_team,
    get_rebalance_report,
    get_utilization_report,
    update_team_capacity,
)
from delta.persistence.database import get_tenant_session
from delta.pm import store as pm_store
from delta.pm.schemas import SprintCreateRequest, TaskCreateRequest
from delta.pm.service import create_sprint, create_task

from .conftest import db_required

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_SPRINT_END = _NOW + timedelta(days=14)


@db_required
async def test_update_team_capacity_missing_team_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(TeamNotFoundError):
            await update_team_capacity(
                session,
                team_id="99999999-9999-4999-8999-999999999999",
                req=TeamCapacityUpdateRequest(tenant_id=tenant_id, capacity_points_per_sprint=10),
            )


@db_required
async def test_assign_task_team_missing_task_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(TaskNotFoundError):
            await assign_task_team(
                session,
                task_id="99999999-9999-4999-8999-999999999999",
                req=TaskTeamAssignRequest(tenant_id=tenant_id, team_id=None),
            )


@db_required
async def test_assign_task_team_missing_team_raises(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        task = await create_task(
            session, TaskCreateRequest(tenant_id=tenant_id, project_id=project_id, title="A")
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(TeamNotFoundError):
            await assign_task_team(
                session,
                task_id=task.task_id,
                req=TaskTeamAssignRequest(
                    tenant_id=tenant_id, team_id="99999999-9999-4999-8999-999999999999"
                ),
            )


@db_required
async def test_assign_task_team_happy_path(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        team = await create_team(
            session,
            TeamCreateRequest(tenant_id=tenant_id, name="Squad", capacity_points_per_sprint=10),
        )
    async with get_tenant_session(tenant_id) as session:
        task = await create_task(
            session, TaskCreateRequest(tenant_id=tenant_id, project_id=project_id, title="A")
        )

    async with get_tenant_session(tenant_id) as session:
        result = await assign_task_team(
            session,
            task_id=task.task_id,
            req=TaskTeamAssignRequest(tenant_id=tenant_id, team_id=team.team_id),
        )
    assert result.team_id == team.team_id


@db_required
async def test_utilization_report_zero_capacity_with_load_is_undefined_ratio(
    tenant_id, project_id
) -> None:
    async with get_tenant_session(tenant_id) as session:
        sprint = await create_sprint(
            session,
            SprintCreateRequest(
                tenant_id=tenant_id,
                project_id=project_id,
                name="Sprint 1",
                start_date=_NOW,
                end_date=_SPRINT_END,
            ),
        )
    async with get_tenant_session(tenant_id) as session:
        team = await create_team(
            session,
            TeamCreateRequest(tenant_id=tenant_id, name="Squad", capacity_points_per_sprint=0),
        )
    async with get_tenant_session(tenant_id) as session:
        task = await create_task(
            session,
            TaskCreateRequest(
                tenant_id=tenant_id,
                project_id=project_id,
                sprint_id=sprint.sprint_id,
                title="Work",
                story_points=5,
            ),
        )
    async with get_tenant_session(tenant_id) as session:
        await assign_task_team(
            session,
            task_id=task.task_id,
            req=TaskTeamAssignRequest(tenant_id=tenant_id, team_id=team.team_id),
        )

    async with get_tenant_session(tenant_id) as session:
        report = await get_utilization_report(
            session, project_id=project_id, sprint_id=sprint.sprint_id
        )

    [row] = report.teams
    assert row.capacity_points_per_sprint == 0
    assert row.remaining_points == 5
    assert row.utilization_ratio is None
    assert report.method == "capacity_ratio_v1"


@db_required
async def test_rebalance_report_suggests_moving_from_over_to_under_team(
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
        overloaded = await create_team(
            session,
            TeamCreateRequest(tenant_id=tenant_id, name="Overloaded", capacity_points_per_sprint=5),
        )
    async with get_tenant_session(tenant_id) as session:
        spare = await create_team(
            session,
            TeamCreateRequest(tenant_id=tenant_id, name="Spare", capacity_points_per_sprint=10),
        )

    async with get_tenant_session(tenant_id) as session:
        task = await create_task(
            session,
            TaskCreateRequest(
                tenant_id=tenant_id,
                project_id=project_id,
                sprint_id=sprint.sprint_id,
                title="Heavy task",
                story_points=8,
            ),
        )
    async with get_tenant_session(tenant_id) as session:
        await assign_task_team(
            session,
            task_id=task.task_id,
            req=TaskTeamAssignRequest(tenant_id=tenant_id, team_id=overloaded.team_id),
        )

    async with get_tenant_session(tenant_id) as session:
        report = await get_rebalance_report(
            session, project_id=project_id, sprint_id=sprint.sprint_id
        )

    assert report.method == "greedy_rebalance_v1"
    assert len(report.suggestions) == 1
    suggestion = report.suggestions[0]
    assert suggestion.task_id == task.task_id
    assert suggestion.from_team_id == overloaded.team_id
    assert suggestion.to_team_id == spare.team_id

    # Advisory only: the suggestion must NOT have mutated the task's actual team.
    async with get_tenant_session(tenant_id) as session:
        fetched = await capacity_store.get_task_for_capacity(session, task_id=task.task_id)
    assert fetched is not None
    assert fetched.team_id == overloaded.team_id
