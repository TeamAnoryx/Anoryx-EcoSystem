"""D-023 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB.

Creates the investment account and its income/expense transactions through the REAL
`personal-finance` HTTP endpoints (D-021) rather than seeding via `store` directly, so
this suite exercises the actual cross-package composition an operator would drive.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .conftest import db_required


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


async def _create_investment_account(client, auth_headers, tenant_id: str) -> str:
    resp = await client.post(
        "/v1/admin/personal-finance/accounts",
        json={
            "tenant_id": tenant_id,
            "type": "investment",
            "currency": "USD",
            "name": "Brokerage",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    return resp.json()["account_id"]


async def _record_transaction(
    client, auth_headers, tenant_id: str, account_id: str, amount_minor_units: int
) -> None:
    resp = await client.post(
        "/v1/admin/personal-finance/transactions",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "category": "income" if amount_minor_units > 0 else "other",
            "amount_minor_units": amount_minor_units,
            "currency": "USD",
            "occurred_at": _iso(5),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201


@db_required
async def test_recommendations_endpoint_401_without_bearer(client, tenant_id) -> None:
    resp = await client.get(f"/v1/admin/asset-allocation/recommendations?tenant_id={tenant_id}")
    assert resp.status_code == 401


@db_required
async def test_risk_tiers_endpoint_returns_fixed_table(client, auth_headers) -> None:
    resp = await client.get("/v1/admin/asset-allocation/risk-tiers", headers=auth_headers)
    assert resp.status_code == 200
    body = {row["risk_tier"]: row for row in resp.json()}
    assert set(body) == {"conservative", "moderate", "aggressive"}
    for row in body.values():
        assert row["cash_pct"] + row["bonds_pct"] + row["equities_pct"] == 100


@db_required
async def test_full_recommendation_flow_over_http(client, auth_headers, tenant_id) -> None:
    account_id = await _create_investment_account(client, auth_headers, tenant_id)
    await _record_transaction(client, auth_headers, tenant_id, account_id, 1000_00)
    await _record_transaction(client, auth_headers, tenant_id, account_id, -300_00)

    rec_resp = await client.post(
        "/v1/admin/asset-allocation/recommendations",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "risk_tier": "moderate",
            "period_start": _iso(30),
            "period_end": _iso(0),
        },
        headers=auth_headers,
    )
    assert rec_resp.status_code == 201
    body = rec_resp.json()
    assert body["surplus_minor_units"] == 700_00
    assert body["recommended_micro_investment_minor_units"] == 70_00
    assert body["cash_pct"] == 20
    assert body["bonds_pct"] == 30
    assert body["equities_pct"] == 50
    assert body["method"] == "risk_tier_target_allocation_v1"

    list_resp = await client.get(
        f"/v1/admin/asset-allocation/recommendations?tenant_id={tenant_id}&account_id={account_id}",
        headers=auth_headers,
    )
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1


@db_required
async def test_recommendation_against_missing_account_returns_404(
    client, auth_headers, tenant_id
) -> None:
    resp = await client.post(
        "/v1/admin/asset-allocation/recommendations",
        json={
            "tenant_id": tenant_id,
            "account_id": "99999999-9999-4999-8999-999999999999",
            "risk_tier": "moderate",
            "period_start": _iso(30),
            "period_end": _iso(0),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_recommendation_against_non_investment_account_returns_422(
    client, auth_headers, tenant_id
) -> None:
    account_resp = await client.post(
        "/v1/admin/personal-finance/accounts",
        json={"tenant_id": tenant_id, "type": "checking", "currency": "USD", "name": "Checking"},
        headers=auth_headers,
    )
    account_id = account_resp.json()["account_id"]

    resp = await client.post(
        "/v1/admin/asset-allocation/recommendations",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "risk_tier": "moderate",
            "period_start": _iso(30),
            "period_end": _iso(0),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_cross_tenant_recommendation_list_isolated_over_http(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    account_id = await _create_investment_account(client, auth_headers, tenant_id)
    await _record_transaction(client, auth_headers, tenant_id, account_id, 500_00)
    await client.post(
        "/v1/admin/asset-allocation/recommendations",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "risk_tier": "moderate",
            "period_start": _iso(30),
            "period_end": _iso(0),
        },
        headers=auth_headers,
    )

    resp = await client.get(
        f"/v1/admin/asset-allocation/recommendations?tenant_id={other_tenant_id}",
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []


@db_required
async def test_invalid_risk_tier_returns_422(client, auth_headers, tenant_id) -> None:
    account_id = await _create_investment_account(client, auth_headers, tenant_id)
    resp = await client.post(
        "/v1/admin/asset-allocation/recommendations",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "risk_tier": "yolo",
            "period_start": _iso(30),
            "period_end": _iso(0),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422
