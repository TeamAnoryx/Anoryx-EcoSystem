"""D-015 non-stubbed PM persistence suite: real store writes -> real SQL reads, real
RLS. Mirrors ``tests/erp/test_store_db.py``'s shape."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from delta.persistence.database import get_tenant_session
from delta.pm import store

from .conftest import db_required

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_START = _NOW
_END = _NOW + timedelta(days=14)


@db_required
async def test_create_and_get_sprint_roundtrip(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_sprint(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            name="Sprint 1",
            start_date=_START,
            end_date=_END,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_sprint(session, sprint_id=created.sprint_id)

    assert fetched is not None
    assert fetched.name == "Sprint 1"
    assert fetched.status == "planned"


@db_required
async def test_task_status_done_sets_completed_at_and_reopening_clears_it(
    tenant_id, project_id
) -> None:
    async with get_tenant_session(tenant_id) as session:
        task = await store.create_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=None,
            title="Build widget",
            story_points=3,
            assignee=None,
            now=_NOW,
        )
        await session.commit()
    assert task.status == "todo"
    assert task.completed_at is None

    async with get_tenant_session(tenant_id) as session:
        await store.update_task_status(session, task_id=task.task_id, status="done", now=_NOW)
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        done = await store.get_task(session, task_id=task.task_id)
    assert done is not None
    assert done.status == "done"
    assert done.completed_at == _NOW

    async with get_tenant_session(tenant_id) as session:
        await store.update_task_status(
            session, task_id=task.task_id, status="in_progress", now=_NOW
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        reopened = await store.get_task(session, task_id=task.task_id)
    assert reopened is not None
    assert reopened.status == "in_progress"
    assert reopened.completed_at is None


@db_required
async def test_velocity_report_computes_completed_points_and_counts(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        sprint = await store.create_sprint(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            name="Sprint 1",
            start_date=_START,
            end_date=_END,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        done_task = await store.create_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=sprint.sprint_id,
            title="Done task",
            story_points=5,
            assignee=None,
            now=_NOW,
        )
        await store.create_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=sprint.sprint_id,
            title="Todo task",
            story_points=3,
            assignee=None,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        await store.update_task_status(session, task_id=done_task.task_id, status="done", now=_NOW)
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        report = await store.get_velocity_report(session, project_id=project_id)

    assert len(report) == 1
    row = report[0]
    assert row.completed_story_points == 5
    assert row.completed_task_count == 1
    assert row.total_task_count == 2


@db_required
async def test_bottleneck_report_ranks_by_blocking_count(tenant_id, project_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        low_fanout = await store.create_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=None,
            title="Low fanout",
            story_points=None,
            assignee=None,
            now=_NOW,
        )
        high_fanout = await store.create_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=None,
            title="High fanout",
            story_points=None,
            assignee=None,
            now=_NOW,
        )
        dependent_1 = await store.create_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=None,
            title="Dependent 1",
            story_points=None,
            assignee=None,
            now=_NOW,
        )
        dependent_2 = await store.create_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=None,
            title="Dependent 2",
            story_points=None,
            assignee=None,
            now=_NOW,
        )
        dependent_3 = await store.create_task(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            sprint_id=None,
            title="Dependent 3",
            story_points=None,
            assignee=None,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        await store.create_dependency(
            session,
            tenant_id=tenant_id,
            blocking_task_id=low_fanout.task_id,
            blocked_task_id=dependent_1.task_id,
            now=_NOW,
        )
        await store.create_dependency(
            session,
            tenant_id=tenant_id,
            blocking_task_id=high_fanout.task_id,
            blocked_task_id=dependent_2.task_id,
            now=_NOW,
        )
        await store.create_dependency(
            session,
            tenant_id=tenant_id,
            blocking_task_id=high_fanout.task_id,
            blocked_task_id=dependent_3.task_id,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        report = await store.get_bottleneck_report(session, project_id=project_id)

    # Only non-done tasks that block at least one other task appear; ranked by
    # blocking_count descending.
    assert [r.task_id for r in report] == [high_fanout.task_id, low_fanout.task_id]
    assert report[0].blocking_count == 2
    assert report[1].blocking_count == 1


@db_required
async def test_cross_tenant_isolation_sprints_invisible_to_other_tenant(
    tenant_id, other_tenant_id, project_id
) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_sprint(
            session,
            tenant_id=tenant_id,
            project_id=project_id,
            name="Sprint 1",
            start_date=_START,
            end_date=_END,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(other_tenant_id) as session:
        fetched = await store.get_sprint(session, sprint_id=created.sprint_id)
        listed = await store.list_sprints(session, project_id=project_id)

    assert fetched is None
    assert listed == []


@db_required
async def test_list_all_dependency_edges_reports_truncation_not_silently_clamped(
    tenant_id, project_id
) -> None:
    # Security-audit finding: this function used to route its limit through
    # `_clamp_limit`/`MAX_LIST_LIMIT` (500) — a pagination bound unrelated to (and far
    # smaller than) the cycle-check's own edge budget — silently truncating the graph
    # fed to the cycle-freedom check for any tenant past 500 edges. It must now return
    # `limit + 1` rows when more than `limit` edges exist, so the caller can detect
    # truncation instead of silently seeing a partial (and thus falsely "acyclic")
    # graph. A small `limit` keeps this test fast while exercising the real contract.
    async with get_tenant_session(tenant_id) as session:
        tasks_ = [
            await store.create_task(
                session,
                tenant_id=tenant_id,
                project_id=project_id,
                sprint_id=None,
                title=f"T{i}",
                story_points=None,
                assignee=None,
                now=_NOW,
            )
            for i in range(4)
        ]
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        for a, b in zip(tasks_, tasks_[1:], strict=False):
            await store.create_dependency(
                session,
                tenant_id=tenant_id,
                blocking_task_id=a.task_id,
                blocked_task_id=b.task_id,
                now=_NOW,
            )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        edges = await store.list_all_dependency_edges(session, limit=2)

    # 3 edges exist (T0->T1, T1->T2, T2->T3); a `limit=2` request must surface that
    # more edges exist by returning `limit + 1 == 3` rows, not silently clamping to 2.
    assert len(edges) == 3
