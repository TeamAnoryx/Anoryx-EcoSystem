"""D-015 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB."""

from __future__ import annotations

from .conftest import db_required


@db_required
async def test_sprints_endpoint_401_without_bearer(client, project_id) -> None:
    resp = await client.get(
        f"/v1/admin/pm/sprints?tenant_id=11111111-1111-4111-8111-111111111111&project_id={project_id}"
    )
    assert resp.status_code == 401


@db_required
async def test_full_pm_flow_over_http(client, auth_headers, tenant_id, project_id) -> None:
    sprint_resp = await client.post(
        "/v1/admin/pm/sprints",
        json={
            "tenant_id": tenant_id,
            "project_id": project_id,
            "name": "Sprint 1",
            "start_date": "2026-07-09T00:00:00Z",
            "end_date": "2026-07-23T00:00:00Z",
        },
        headers=auth_headers,
    )
    assert sprint_resp.status_code == 201
    sprint = sprint_resp.json()
    assert sprint["status"] == "planned"

    blocking_resp = await client.post(
        "/v1/admin/pm/tasks",
        json={
            "tenant_id": tenant_id,
            "project_id": project_id,
            "sprint_id": sprint["sprint_id"],
            "title": "Design the API",
            "story_points": 3,
        },
        headers=auth_headers,
    )
    assert blocking_resp.status_code == 201
    blocking_task = blocking_resp.json()

    blocked_resp = await client.post(
        "/v1/admin/pm/tasks",
        json={
            "tenant_id": tenant_id,
            "project_id": project_id,
            "sprint_id": sprint["sprint_id"],
            "title": "Implement the API",
            "story_points": 5,
        },
        headers=auth_headers,
    )
    assert blocked_resp.status_code == 201
    blocked_task = blocked_resp.json()

    dep_resp = await client.post(
        "/v1/admin/pm/dependencies",
        json={
            "tenant_id": tenant_id,
            "blocking_task_id": blocking_task["task_id"],
            "blocked_task_id": blocked_task["task_id"],
        },
        headers=auth_headers,
    )
    assert dep_resp.status_code == 201

    # "Implement the API" (blocked, not done) should show up in the bottleneck
    # report once we mark "Design the API" still not-done — but the bottleneck
    # report should surface the BLOCKING task (Design), which currently blocks 1.
    bottlenecks_resp = await client.get(
        f"/v1/admin/pm/bottlenecks?tenant_id={tenant_id}&project_id={project_id}",
        headers=auth_headers,
    )
    assert bottlenecks_resp.status_code == 200
    bottleneck_report = bottlenecks_resp.json()
    assert bottleneck_report["method"] == "blocking_fanout_v1"
    assert len(bottleneck_report["bottlenecks"]) == 1
    assert bottleneck_report["bottlenecks"][0]["task_id"] == blocking_task["task_id"]
    assert bottleneck_report["bottlenecks"][0]["blocking_count"] == 1

    # Complete the blocking task — it should drop out of the bottleneck report.
    complete_resp = await client.post(
        f"/v1/admin/pm/tasks/{blocking_task['task_id']}/status",
        json={"tenant_id": tenant_id, "status": "done"},
        headers=auth_headers,
    )
    assert complete_resp.status_code == 200
    assert complete_resp.json()["status"] == "done"

    bottlenecks_after_resp = await client.get(
        f"/v1/admin/pm/bottlenecks?tenant_id={tenant_id}&project_id={project_id}",
        headers=auth_headers,
    )
    assert bottlenecks_after_resp.json()["bottlenecks"] == []

    velocity_resp = await client.get(
        f"/v1/admin/pm/velocity?tenant_id={tenant_id}&project_id={project_id}",
        headers=auth_headers,
    )
    assert velocity_resp.status_code == 200
    velocity = velocity_resp.json()
    [sprint_row] = velocity["sprints"]
    assert sprint_row["completed_story_points"] == 3
    assert sprint_row["completed_task_count"] == 1
    assert sprint_row["total_task_count"] == 2


@db_required
async def test_dependency_cycle_returns_422_over_http(
    client, auth_headers, tenant_id, project_id
) -> None:
    task_a = (
        await client.post(
            "/v1/admin/pm/tasks",
            json={"tenant_id": tenant_id, "project_id": project_id, "title": "A"},
            headers=auth_headers,
        )
    ).json()
    task_b = (
        await client.post(
            "/v1/admin/pm/tasks",
            json={"tenant_id": tenant_id, "project_id": project_id, "title": "B"},
            headers=auth_headers,
        )
    ).json()

    first_edge_resp = await client.post(
        "/v1/admin/pm/dependencies",
        json={
            "tenant_id": tenant_id,
            "blocking_task_id": task_a["task_id"],
            "blocked_task_id": task_b["task_id"],
        },
        headers=auth_headers,
    )
    assert first_edge_resp.status_code == 201

    cycle_resp = await client.post(
        "/v1/admin/pm/dependencies",
        json={
            "tenant_id": tenant_id,
            "blocking_task_id": task_b["task_id"],
            "blocked_task_id": task_a["task_id"],
        },
        headers=auth_headers,
    )
    assert cycle_resp.status_code == 422


@db_required
async def test_self_dependency_returns_422_over_http(
    client, auth_headers, tenant_id, project_id
) -> None:
    task = (
        await client.post(
            "/v1/admin/pm/tasks",
            json={"tenant_id": tenant_id, "project_id": project_id, "title": "A"},
            headers=auth_headers,
        )
    ).json()

    resp = await client.post(
        "/v1/admin/pm/dependencies",
        json={
            "tenant_id": tenant_id,
            "blocking_task_id": task["task_id"],
            "blocked_task_id": task["task_id"],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_cross_tenant_sprint_list_isolated_over_http(
    client, auth_headers, tenant_id, other_tenant_id, project_id
) -> None:
    await client.post(
        "/v1/admin/pm/sprints",
        json={
            "tenant_id": tenant_id,
            "project_id": project_id,
            "name": "Tenant A's Sprint",
            "start_date": "2026-07-09T00:00:00Z",
            "end_date": "2026-07-23T00:00:00Z",
        },
        headers=auth_headers,
    )

    resp = await client.get(
        f"/v1/admin/pm/sprints?tenant_id={other_tenant_id}&project_id={project_id}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []
