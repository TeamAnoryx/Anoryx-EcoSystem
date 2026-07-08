"""D-008 non-stubbed HTTP e2e: the real ASGI app, real auth, real DB, real posted usage."""

from __future__ import annotations

import uuid

import httpx

from .conftest import db_required

_START = "2026-07-01T00:00:00Z"
_END = "2026-07-03T00:00:00Z"


async def test_summary_missing_bearer_is_401(client: httpx.AsyncClient, tenant_id: str) -> None:
    resp = await client.get(
        "/v1/admin/dashboards/summary",
        params={"tenant_id": tenant_id, "start": _START, "end": _END},
    )
    assert resp.status_code == 401


@db_required
async def test_summary_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, seed_usage
) -> None:
    await seed_usage(tenant_id=tenant_id, cost_cents=4_200, timestamp="2026-07-01T10:00:00Z")

    resp = await client.get(
        "/v1/admin/dashboards/summary",
        params={"tenant_id": tenant_id, "start": _START, "end": _END},
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_cost_cents"] == 4_200
    assert body["request_count"] == 1
    assert body["cost_per_request_cents"] == 4_200.0


@db_required
async def test_timeseries_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, seed_usage
) -> None:
    await seed_usage(tenant_id=tenant_id, cost_cents=1_000, timestamp="2026-07-01T10:00:00Z")
    await seed_usage(tenant_id=tenant_id, cost_cents=2_000, timestamp="2026-07-02T10:00:00Z")

    resp = await client.get(
        "/v1/admin/dashboards/timeseries",
        params={"tenant_id": tenant_id, "start": _START, "end": _END, "bucket": "day"},
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    points = resp.json()
    assert len(points) == 2
    assert [p["cost_cents"] for p in points] == [1_000, 2_000]


@db_required
async def test_top_spenders_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, seed_usage
) -> None:
    await seed_usage(tenant_id=tenant_id, agent_id="agent-a", cost_cents=100)
    await seed_usage(tenant_id=tenant_id, agent_id="agent-b", cost_cents=9_000)

    resp = await client.get(
        "/v1/admin/dashboards/top-spenders",
        params={
            "tenant_id": tenant_id,
            "start": _START,
            "end": _END,
            "group_by": "agent_id",
            "limit": 5,
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    ranked = resp.json()
    assert ranked[0]["group_key"] == "agent-b"
    assert ranked[0]["cost_cents"] == 9_000


@db_required
async def test_top_spenders_group_by_pinned_scope_is_422(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    team_id = str(uuid.uuid4())
    resp = await client.get(
        "/v1/admin/dashboards/top-spenders",
        params={
            "tenant_id": tenant_id,
            "start": _START,
            "end": _END,
            "group_by": "team_id",
            "team_id": team_id,
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_inverted_window_is_422(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    resp = await client.get(
        "/v1/admin/dashboards/summary",
        params={"tenant_id": tenant_id, "start": _END, "end": _START},
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_cross_tenant_summary_is_isolated_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, other_tenant_id: str, seed_usage
) -> None:
    await seed_usage(tenant_id=tenant_id, cost_cents=1_000)
    await seed_usage(tenant_id=other_tenant_id, cost_cents=8_000)

    resp = await client.get(
        "/v1/admin/dashboards/summary",
        params={"tenant_id": tenant_id, "start": _START, "end": _END},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["total_cost_cents"] == 1_000
