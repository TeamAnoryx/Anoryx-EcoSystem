"""D-011 non-stubbed HTTP e2e: the real ASGI app, real auth, real DB, real budgets/usage.

The router resolves ``now`` from the real wall clock (mirrors every other Delta admin
endpoint — none take a client-supplied "now"), so unlike ``test_service_db.py`` these
tests cannot pin an explicit period boundary. Usage is seeded a few minutes in the past
(mirrors ``budget_engine``'s own ``_recent_ts()`` e2e-test pattern) — safely within the
current MONTHLY period except in the improbable case a test runs in the first few minutes
of a calendar month, the same accepted tiny risk that pattern already carries elsewhere.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import httpx

from delta.budget import BudgetScope

from .conftest import db_required


def _recent_ts() -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")


async def test_get_forecast_missing_bearer_is_401(
    client: httpx.AsyncClient, tenant_id: str
) -> None:
    resp = await client.get(
        f"/v1/admin/forecast/budgets/{uuid.uuid4()}", params={"tenant_id": tenant_id}
    )
    assert resp.status_code == 401


@db_required
async def test_get_forecast_404_for_unknown_budget(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    resp = await client.get(
        f"/v1/admin/forecast/budgets/{uuid.uuid4()}",
        params={"tenant_id": tenant_id},
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_get_forecast_happy_path_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, make_budget, seed_usage
) -> None:
    budget = await make_budget(tenant_id=tenant_id, cap_cents=1000_00, scope=BudgetScope.TENANT)
    await seed_usage(tenant_id=tenant_id, cost_cents=850_00, timestamp=_recent_ts())

    resp = await client.get(
        f"/v1/admin/forecast/budgets/{budget.budget_id}",
        params={"tenant_id": tenant_id},
        headers=auth_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["budget_id"] == budget.budget_id
    assert body["current_period_spend_cents"] == 850_00
    assert body["method"] == "current_rate_projection_v1"
    assert any(r["code"] == "SOFT_THRESHOLD_CROSSED" for r in body["recommendations"])


@db_required
async def test_list_forecasts_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, make_budget
) -> None:
    b1 = await make_budget(tenant_id=tenant_id, cap_cents=1000_00)
    b2 = await make_budget(tenant_id=tenant_id, cap_cents=2000_00, scope=BudgetScope.TEAM)

    resp = await client.get(
        "/v1/admin/forecast/budgets", params={"tenant_id": tenant_id}, headers=auth_headers
    )
    assert resp.status_code == 200, resp.text
    ids = {r["budget_id"] for r in resp.json()}
    assert ids == {b1.budget_id, b2.budget_id}


@db_required
async def test_cross_tenant_forecast_is_isolated_over_http(
    client: httpx.AsyncClient,
    auth_headers: dict,
    tenant_id: str,
    other_tenant_id: str,
    make_budget,
) -> None:
    budget = await make_budget(tenant_id=tenant_id, cap_cents=1000_00)

    resp = await client.get(
        f"/v1/admin/forecast/budgets/{budget.budget_id}",
        params={"tenant_id": other_tenant_id},
        headers=auth_headers,
    )
    assert resp.status_code == 404

    resp_list = await client.get(
        "/v1/admin/forecast/budgets",
        params={"tenant_id": other_tenant_id},
        headers=auth_headers,
    )
    assert resp_list.status_code == 200
    assert resp_list.json() == []
