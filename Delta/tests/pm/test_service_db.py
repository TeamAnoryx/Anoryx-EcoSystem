"""D-015 service-layer DB tests: exception mapping + the dependency-cycle check
against a real graph (delta.pm.service).

Each mutating service call commits — a new ``get_tenant_session`` block is opened per
commit, never reused across two writes (same discipline as ``tests/erp/test_service_db.py``).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from delta.persistence.database import get_tenant_session
from delta.pm.schemas import (
    SprintCreateRequest,
    SprintStatusUpdateRequest,
    TaskCreateRequest,
    TaskDependencyCreateRequest,
    TaskStatusUpdateRequest,
)
from delta.pm.service import (
    DependencyCycleError,
    SelfDependencyError,
    SprintNotFoundError,
    TaskNotFoundError,
    create_dependency,
    create_sprint,
    create_task,
    update_sprint_status,
    update_task_status,
)

from .conftest import db_required

_START = datetime(2026, 7, 9, tzinfo=timezone.utc)
_END = _START + timedelta(days=14)


@db_required
async def test_create_task_against_missing_sprint_raises(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(SprintNotFoundError):
            await create_task(
                session,
                TaskCreateRequest(
                    tenant_id=tenant_id,
                    project_id=project_id,
                    sprint_id="99999999-9999-4999-8999-999999999999",
                    title="Ghost task",
                ),
            )


@db_required
async def test_update_sprint_status_missing_sprint_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(SprintNotFoundError):
            await update_sprint_status(
                session,
                sprint_id="99999999-9999-4999-8999-999999999999",
                req=SprintStatusUpdateRequest(tenant_id=tenant_id, status="active"),
            )


@db_required
async def test_update_task_status_missing_task_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(TaskNotFoundError):
            await update_task_status(
                session,
                task_id="99999999-9999-4999-8999-999999999999",
                req=TaskStatusUpdateRequest(tenant_id=tenant_id, status="done"),
            )


@db_required
async def test_create_dependency_self_reference_raises(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        task = await create_task(
            session, TaskCreateRequest(tenant_id=tenant_id, project_id=project_id, title="A")
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(SelfDependencyError):
            await create_dependency(
                session,
                TaskDependencyCreateRequest(
                    tenant_id=tenant_id,
                    blocking_task_id=task.task_id,
                    blocked_task_id=task.task_id,
                ),
            )


@db_required
async def test_create_dependency_missing_task_raises(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        task = await create_task(
            session, TaskCreateRequest(tenant_id=tenant_id, project_id=project_id, title="A")
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(TaskNotFoundError):
            await create_dependency(
                session,
                TaskDependencyCreateRequest(
                    tenant_id=tenant_id,
                    blocking_task_id=task.task_id,
                    blocked_task_id="99999999-9999-4999-8999-999999999999",
                ),
            )


@db_required
async def test_create_dependency_cycle_rejected_against_real_graph(tenant_id, project_id) -> None:
    # A -> B -> C already exists (real rows, real edges). Adding "C blocks A" must be
    # rejected as a cycle by the service, backed by a real DB read of the edge list.
    async with get_tenant_session(tenant_id) as session:
        task_a = await create_task(
            session, TaskCreateRequest(tenant_id=tenant_id, project_id=project_id, title="A")
        )
    async with get_tenant_session(tenant_id) as session:
        task_b = await create_task(
            session, TaskCreateRequest(tenant_id=tenant_id, project_id=project_id, title="B")
        )
    async with get_tenant_session(tenant_id) as session:
        task_c = await create_task(
            session, TaskCreateRequest(tenant_id=tenant_id, project_id=project_id, title="C")
        )

    async with get_tenant_session(tenant_id) as session:
        await create_dependency(
            session,
            TaskDependencyCreateRequest(
                tenant_id=tenant_id, blocking_task_id=task_a.task_id, blocked_task_id=task_b.task_id
            ),
        )
    async with get_tenant_session(tenant_id) as session:
        await create_dependency(
            session,
            TaskDependencyCreateRequest(
                tenant_id=tenant_id, blocking_task_id=task_b.task_id, blocked_task_id=task_c.task_id
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(DependencyCycleError):
            await create_dependency(
                session,
                TaskDependencyCreateRequest(
                    tenant_id=tenant_id,
                    blocking_task_id=task_c.task_id,
                    blocked_task_id=task_a.task_id,
                ),
            )


@db_required
async def test_create_sprint_and_task_happy_path(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        sprint = await create_sprint(
            session,
            SprintCreateRequest(
                tenant_id=tenant_id,
                project_id=project_id,
                name="Sprint 1",
                start_date=_START,
                end_date=_END,
            ),
        )
    assert sprint.status == "planned"

    async with get_tenant_session(tenant_id) as session:
        task = await create_task(
            session,
            TaskCreateRequest(
                tenant_id=tenant_id,
                project_id=project_id,
                sprint_id=sprint.sprint_id,
                title="Build widget",
                story_points=5,
            ),
        )
    assert task.sprint_id == sprint.sprint_id
    assert task.status == "todo"
