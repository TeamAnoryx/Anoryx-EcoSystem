"""D-020 non-stubbed HTTP e2e: the real ASGI app, real auth, real DB, real
budgets/usage/CRM data. Mirrors ``tests/forecasting/test_router_e2e.py``: the router
resolves ``now`` from the real wall clock (this task does not add a client-supplied
"now" — no other Delta admin endpoint takes one), so usage is seeded a few minutes in
the past rather than pinned to an explicit period boundary."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx

from .conftest import db_required, seed_client_and_deal


def _recent_ts() -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")


async def test_get_summary_missing_bearer_is_401(client: httpx.AsyncClient, tenant_id: str) -> None:
    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/v1/admin/executive/summary",
        params={
            "tenant_id": tenant_id,
            "start": (now - timedelta(days=1)).isoformat(),
            "end": now.isoformat(),
        },
    )
    assert resp.status_code == 401


@db_required
async def test_get_summary_rejects_end_before_start_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/v1/admin/executive/summary",
        params={
            "tenant_id": tenant_id,
            "start": now.isoformat(),
            "end": (now - timedelta(days=1)).isoformat(),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_get_summary_happy_path_over_http(
    client: httpx.AsyncClient,
    auth_headers: dict,
    tenant_id: str,
    make_budget,
    seed_usage,
) -> None:
    await make_budget(tenant_id=tenant_id, cap_cents=1000_00)
    await seed_usage(tenant_id=tenant_id, cost_cents=850_00, timestamp=_recent_ts())
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=42_000, stage="qualified")

    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/v1/admin/executive/summary",
        params={
            "tenant_id": tenant_id,
            "start": (now - timedelta(days=1)).isoformat(),
            "end": now.isoformat(),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_cost_cents"] == 850_00
    assert body["budget_count"] == 1
    assert body["total_current_period_spend_cents"] == 850_00
    assert body["client_count"] == 1
    assert body["open_deal_count"] == 1
    assert body["open_pipeline_value_minor_units"] == 42_000
    assert body["pipeline_currency"] == "USD"


@db_required
async def test_cross_tenant_summary_is_isolated_over_http(
    client: httpx.AsyncClient,
    auth_headers: dict,
    tenant_id: str,
    other_tenant_id: str,
    make_budget,
    seed_usage,
) -> None:
    await make_budget(tenant_id=tenant_id, cap_cents=1000_00)
    await seed_usage(tenant_id=tenant_id, cost_cents=500_00, timestamp=_recent_ts())
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=10_000, stage="qualified")

    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/v1/admin/executive/summary",
        params={
            "tenant_id": other_tenant_id,
            "start": (now - timedelta(days=1)).isoformat(),
            "end": now.isoformat(),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total_cost_cents"] == 0
    assert body["budget_count"] == 0
    assert body["client_count"] == 0
    assert body["open_deal_count"] == 0
    assert body["open_pipeline_value_minor_units"] == 0
