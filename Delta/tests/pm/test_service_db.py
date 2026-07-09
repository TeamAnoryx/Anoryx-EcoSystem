"""D-015 service-layer DB tests: exception mapping + the dependency-cycle check
against a real graph (delta.pm.service).

Each mutating service call commits — a new ``get_tenant_session`` block is opened per
commit, never reused across two writes (same discipline as ``tests/erp/test_service_db.py``).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from delta.persistence.database import get_tenant_session
from delta.pm import service as pm_service
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
    TooManyDependencyEdgesError,
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


@db_required
async def test_create_dependency_race_is_serialized_by_advisory_lock(tenant_id, project_id) -> None:
    # Security-audit finding: two concurrent create_dependency calls for opposite
    # edges between the same two tasks (A->B and B->A) are each individually
    # cycle-free against the committed graph — without serialization, both could
    # read-check-then-insert before either commits and jointly close a 2-node cycle.
    # `create_dependency`'s `pg_advisory_xact_lock(hashtext(tenant_id))` (mirroring
    # D-009's `append_history` lock) must force exactly one to observe the other's
    # edge and be rejected as a cycle.
    async with get_tenant_session(tenant_id) as session:
        task_a = await create_task(
            session, TaskCreateRequest(tenant_id=tenant_id, project_id=project_id, title="A")
        )
    async with get_tenant_session(tenant_id) as session:
        task_b = await create_task(
            session, TaskCreateRequest(tenant_id=tenant_id, project_id=project_id, title="B")
        )

    async def link(blocking_id: str, blocked_id: str):
        async with get_tenant_session(tenant_id) as session:
            return await create_dependency(
                session,
                TaskDependencyCreateRequest(
                    tenant_id=tenant_id, blocking_task_id=blocking_id, blocked_task_id=blocked_id
                ),
            )

    results = await asyncio.gather(
        link(task_a.task_id, task_b.task_id),
        link(task_b.task_id, task_a.task_id),
        return_exceptions=True,
    )

    successes = [r for r in results if not isinstance(r, BaseException)]
    failures = [r for r in results if isinstance(r, BaseException)]
    assert len(successes) == 1, f"expected exactly one edge to win the race, got: {results}"
    assert len(failures) == 1
    assert isinstance(failures[0], DependencyCycleError)

    async with get_tenant_session(tenant_id) as session:
        edges = await pm_service.store.list_all_dependency_edges(session)
    assert len(edges) == 1, "the race must not leave a closed 2-node cycle in the graph"


@db_required
async def test_create_dependency_fails_closed_when_edge_bound_reached(
    monkeypatch, tenant_id, project_id
) -> None:
    # Security-audit finding: `list_all_dependency_edges` used to be silently routed
    # through the pagination clamp (MAX_LIST_LIMIT=500), truncating the graph fed to
    # the cycle check for any tenant past that many edges — the check would then
    # accept a cycle-closing edge it never saw. The fix fails closed instead: if more
    # edges exist than `MAX_DEPENDENCY_EDGES_CONSIDERED` allows, the create is
    # rejected rather than checked against a possibly-incomplete graph.

    async def make_task(title: str):
        async with get_tenant_session(tenant_id) as session:
            return await create_task(
                session, TaskCreateRequest(tenant_id=tenant_id, project_id=project_id, title=title)
            )

    t0, t1, t2, t3 = [await make_task(f"T{i}") for i in range(4)]

    async def link(blocking_id: str, blocked_id: str):
        async with get_tenant_session(tenant_id) as session:
            return await create_dependency(
                session,
                TaskDependencyCreateRequest(
                    tenant_id=tenant_id, blocking_task_id=blocking_id, blocked_task_id=blocked_id
                ),
            )

    # Build 2 edges under the real (2000) bound — both succeed normally.
    await link(t0.task_id, t1.task_id)
    await link(t1.task_id, t2.task_id)

    # Now lower the bound below the graph's actual edge count (2) — a third edge
    # attempt must fail closed rather than risk running the cycle check against a
    # truncated edge set (list_all_dependency_edges would return 2 rows, exceeding
    # the now-lowered bound of 1).
    monkeypatch.setattr(pm_service, "MAX_DEPENDENCY_EDGES_CONSIDERED", 1)
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(TooManyDependencyEdgesError):
            await create_dependency(
                session,
                TaskDependencyCreateRequest(
                    tenant_id=tenant_id, blocking_task_id=t2.task_id, blocked_task_id=t3.task_id
                ),
            )
