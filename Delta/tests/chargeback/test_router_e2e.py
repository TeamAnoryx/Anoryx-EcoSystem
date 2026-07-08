"""D-012 non-stubbed HTTP e2e: the real ASGI app, real auth, real DB, real posted usage."""

from __future__ import annotations

import uuid

import httpx

from .conftest import db_required

_CURRENT_START = "2026-07-08T00:00:00Z"
_CURRENT_END = "2026-07-09T00:00:00Z"


async def test_report_missing_bearer_is_401(client: httpx.AsyncClient, tenant_id: str) -> None:
    resp = await client.get(
        "/v1/admin/chargeback/report",
        params={
            "tenant_id": tenant_id,
            "start": _CURRENT_START,
            "end": _CURRENT_END,
            "group_by": "team_id",
        },
    )
    assert resp.status_code == 401


async def test_anomalies_missing_bearer_is_401(client: httpx.AsyncClient, tenant_id: str) -> None:
    resp = await client.get(
        "/v1/admin/chargeback/anomalies",
        params={
            "tenant_id": tenant_id,
            "start": _CURRENT_START,
            "end": _CURRENT_END,
            "group_by": "team_id",
        },
    )
    assert resp.status_code == 401


@db_required
async def test_report_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, seed_usage
) -> None:
    team_a = str(uuid.uuid4())
    await seed_usage(
        tenant_id=tenant_id, team_id=team_a, cost_cents=4_200, timestamp=_CURRENT_START
    )

    resp = await client.get(
        "/v1/admin/chargeback/report",
        params={
            "tenant_id": tenant_id,
            "start": _CURRENT_START,
            "end": _CURRENT_END,
            "group_by": "team_id",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_cost_cents"] == 4_200
    assert body["rows"][0]["group_key"] == team_a
    assert body["rows"][0]["share_pct"] == 100.0


@db_required
async def test_report_group_by_pinned_scope_is_422(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    team_id = str(uuid.uuid4())
    resp = await client.get(
        "/v1/admin/chargeback/report",
        params={
            "tenant_id": tenant_id,
            "start": _CURRENT_START,
            "end": _CURRENT_END,
            "group_by": "team_id",
            "team_id": team_id,
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_anomalies_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, seed_usage
) -> None:
    team = str(uuid.uuid4())
    for day in range(1, 8):
        await seed_usage(
            tenant_id=tenant_id,
            team_id=team,
            cost_cents=10_00,
            timestamp=f"2026-07-{day:02d}T06:00:00Z",
        )
    await seed_usage(tenant_id=tenant_id, team_id=team, cost_cents=50_00, timestamp=_CURRENT_START)

    resp = await client.get(
        "/v1/admin/chargeback/anomalies",
        params={
            "tenant_id": tenant_id,
            "start": _CURRENT_START,
            "end": _CURRENT_END,
            "group_by": "team_id",
            "baseline_periods": 7,
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["method"] == "trailing_average_ratio_v1"
    assert len(body["anomalies"]) == 1
    assert body["anomalies"][0]["code"] == "SPEND_SPIKE"
    assert body["anomalies"][0]["group_key"] == team


@db_required
async def test_anomalies_baseline_span_too_large_is_422(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    resp = await client.get(
        "/v1/admin/chargeback/anomalies",
        params={
            "tenant_id": tenant_id,
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-07-20T00:00:00Z",  # ~200-day window
            "group_by": "team_id",
            "baseline_periods": 3,  # x3 -> ~600 days, over the 400-day cap
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_cross_tenant_report_is_isolated_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, other_tenant_id: str, seed_usage
) -> None:
    await seed_usage(tenant_id=tenant_id, cost_cents=1_000, timestamp=_CURRENT_START)
    await seed_usage(tenant_id=other_tenant_id, cost_cents=8_000, timestamp=_CURRENT_START)

    resp = await client.get(
        "/v1/admin/chargeback/report",
        params={
            "tenant_id": tenant_id,
            "start": _CURRENT_START,
            "end": _CURRENT_END,
            "group_by": "team_id",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["total_cost_cents"] == 1_000
