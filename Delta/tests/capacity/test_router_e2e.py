"""D-016 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB."""

from __future__ import annotations

from .conftest import db_required


@db_required
async def test_teams_endpoint_401_without_bearer(client, tenant_id) -> None:
    resp = await client.get(f"/v1/admin/capacity/teams?tenant_id={tenant_id}")
    assert resp.status_code == 401


@db_required
async def test_full_capacity_flow_over_http(client, auth_headers, tenant_id, project_id) -> None:
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

    overloaded_resp = await client.post(
        "/v1/admin/capacity/teams",
        json={"tenant_id": tenant_id, "name": "Overloaded", "capacity_points_per_sprint": 5},
        headers=auth_headers,
    )
    assert overloaded_resp.status_code == 201
    overloaded = overloaded_resp.json()

    spare_resp = await client.post(
        "/v1/admin/capacity/teams",
        json={"tenant_id": tenant_id, "name": "Spare", "capacity_points_per_sprint": 10},
        headers=auth_headers,
    )
    assert spare_resp.status_code == 201
    spare = spare_resp.json()

    task_resp = await client.post(
        "/v1/admin/pm/tasks",
        json={
            "tenant_id": tenant_id,
            "project_id": project_id,
            "sprint_id": sprint["sprint_id"],
            "title": "Heavy task",
            "story_points": 8,
        },
        headers=auth_headers,
    )
    assert task_resp.status_code == 201
    task = task_resp.json()

    assign_resp = await client.post(
        f"/v1/admin/capacity/tasks/{task['task_id']}/team",
        json={"tenant_id": tenant_id, "team_id": overloaded["team_id"]},
        headers=auth_headers,
    )
    assert assign_resp.status_code == 200
    assert assign_resp.json()["team_id"] == overloaded["team_id"]

    tasks_resp = await client.get(
        f"/v1/admin/capacity/tasks?tenant_id={tenant_id}&project_id={project_id}"
        f"&sprint_id={sprint['sprint_id']}",
        headers=auth_headers,
    )
    assert tasks_resp.status_code == 200
    [capacity_task] = tasks_resp.json()
    assert capacity_task["task_id"] == task["task_id"]
    assert capacity_task["team_id"] == overloaded["team_id"]

    utilization_resp = await client.get(
        f"/v1/admin/capacity/utilization?tenant_id={tenant_id}&project_id={project_id}"
        f"&sprint_id={sprint['sprint_id']}",
        headers=auth_headers,
    )
    assert utilization_resp.status_code == 200
    utilization = utilization_resp.json()
    assert utilization["method"] == "capacity_ratio_v1"
    by_id = {row["team_id"]: row for row in utilization["teams"]}
    assert by_id[overloaded["team_id"]]["remaining_points"] == 8
    assert by_id[overloaded["team_id"]]["utilization_ratio"] == 8 / 5
    assert by_id[spare["team_id"]]["remaining_points"] == 0

    rebalance_resp = await client.get(
        f"/v1/admin/capacity/rebalance?tenant_id={tenant_id}&project_id={project_id}"
        f"&sprint_id={sprint['sprint_id']}",
        headers=auth_headers,
    )
    assert rebalance_resp.status_code == 200
    rebalance = rebalance_resp.json()
    assert rebalance["method"] == "greedy_rebalance_v1"
    assert len(rebalance["suggestions"]) == 1
    suggestion = rebalance["suggestions"][0]
    assert suggestion["task_id"] == task["task_id"]
    assert suggestion["from_team_id"] == overloaded["team_id"]
    assert suggestion["to_team_id"] == spare["team_id"]

    # Apply the suggestion explicitly (the rebalance report never mutates anything
    # itself — advisory only).
    apply_resp = await client.post(
        f"/v1/admin/capacity/tasks/{task['task_id']}/team",
        json={"tenant_id": tenant_id, "team_id": spare["team_id"]},
        headers=auth_headers,
    )
    assert apply_resp.status_code == 200
    assert apply_resp.json()["team_id"] == spare["team_id"]

    rebalance_after_resp = await client.get(
        f"/v1/admin/capacity/rebalance?tenant_id={tenant_id}&project_id={project_id}"
        f"&sprint_id={sprint['sprint_id']}",
        headers=auth_headers,
    )
    assert rebalance_after_resp.json()["suggestions"] == []


@db_required
async def test_assign_task_team_404_for_missing_team(
    client, auth_headers, tenant_id, project_id
) -> None:
    task_resp = await client.post(
        "/v1/admin/pm/tasks",
        json={"tenant_id": tenant_id, "project_id": project_id, "title": "A"},
        headers=auth_headers,
    )
    task = task_resp.json()

    resp = await client.post(
        f"/v1/admin/capacity/tasks/{task['task_id']}/team",
        json={"tenant_id": tenant_id, "team_id": "99999999-9999-4999-8999-999999999999"},
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_team_capacity_update_404_for_missing_team(client, auth_headers, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/capacity/teams/99999999-9999-4999-8999-999999999999/capacity",
        json={"tenant_id": tenant_id, "capacity_points_per_sprint": 10},
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_cross_tenant_team_list_isolated_over_http(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    await client.post(
        "/v1/admin/capacity/teams",
        json={"tenant_id": tenant_id, "name": "Tenant A's Squad", "capacity_points_per_sprint": 10},
        headers=auth_headers,
    )

    resp = await client.get(
        f"/v1/admin/capacity/teams?tenant_id={other_tenant_id}", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json() == []
