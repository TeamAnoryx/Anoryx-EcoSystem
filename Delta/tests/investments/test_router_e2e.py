"""D-023 non-stubbed HTTP e2e: the real ASGI app, real auth, real DB. Drives a full
investment-account -> holding -> allocation-recommendation flow over HTTP."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx

from .conftest import db_required


def _recent_iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


async def test_holdings_endpoint_401_without_bearer(
    client: httpx.AsyncClient, tenant_id: str
) -> None:
    resp = await client.get("/v1/admin/investments/holdings", params={"tenant_id": tenant_id})
    assert resp.status_code == 401


@db_required
async def test_full_holding_and_recommendation_flow_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    account_resp = await client.post(
        "/v1/admin/personal-finance/accounts",
        json={"tenant_id": tenant_id, "type": "investment", "currency": "USD", "name": "Brokerage"},
        headers=auth_headers,
    )
    assert account_resp.status_code == 201, account_resp.text
    account_id = account_resp.json()["account_id"]

    holding_resp = await client.post(
        "/v1/admin/investments/holdings",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "asset_class": "stocks",
            "value_minor_units": 500_000,
            "currency": "USD",
        },
        headers=auth_headers,
    )
    assert holding_resp.status_code == 201, holding_resp.text

    holdings_resp = await client.get(
        "/v1/admin/investments/holdings", params={"tenant_id": tenant_id}, headers=auth_headers
    )
    assert holdings_resp.status_code == 200
    assert len(holdings_resp.json()) == 1
    assert holdings_resp.json()[0]["asset_class"] == "stocks"

    now = datetime.now(timezone.utc)
    rec_resp = await client.get(
        "/v1/admin/investments/allocation-recommendation",
        params={
            "tenant_id": tenant_id,
            "risk_profile": "moderate",
            "start": (now - timedelta(days=30)).isoformat(),
            "end": now.isoformat(),
        },
        headers=auth_headers,
    )
    assert rec_resp.status_code == 200, rec_resp.text
    body = rec_resp.json()
    assert body["total_portfolio_value_minor_units"] == 500_000
    assert body["method"] == "fixed_target_weights_v1"
    assert len(body["lines"]) == 6


@db_required
async def test_holding_against_unknown_account_returns_404(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    resp = await client.post(
        "/v1/admin/investments/holdings",
        json={
            "tenant_id": tenant_id,
            "account_id": "99999999-9999-4999-8999-999999999999",
            "asset_class": "stocks",
            "value_minor_units": 1000,
            "currency": "USD",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_holding_against_non_investment_account_returns_422(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    account_resp = await client.post(
        "/v1/admin/personal-finance/accounts",
        json={"tenant_id": tenant_id, "type": "checking", "currency": "USD", "name": "Checking"},
        headers=auth_headers,
    )
    assert account_resp.status_code == 201
    account_id = account_resp.json()["account_id"]

    resp = await client.post(
        "/v1/admin/investments/holdings",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "asset_class": "stocks",
            "value_minor_units": 1000,
            "currency": "USD",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_allocation_recommendation_rejects_end_before_start_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/v1/admin/investments/allocation-recommendation",
        params={
            "tenant_id": tenant_id,
            "risk_profile": "moderate",
            "start": now.isoformat(),
            "end": (now - timedelta(days=1)).isoformat(),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_allocation_recommendation_rejects_unknown_risk_profile_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/v1/admin/investments/allocation-recommendation",
        params={
            "tenant_id": tenant_id,
            "risk_profile": "yolo",
            "start": (now - timedelta(days=1)).isoformat(),
            "end": now.isoformat(),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_cross_tenant_holdings_isolated_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, other_tenant_id: str
) -> None:
    account_resp = await client.post(
        "/v1/admin/personal-finance/accounts",
        json={"tenant_id": tenant_id, "type": "investment", "currency": "USD", "name": "Brokerage"},
        headers=auth_headers,
    )
    assert account_resp.status_code == 201
    account_id = account_resp.json()["account_id"]

    create_resp = await client.post(
        "/v1/admin/investments/holdings",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "asset_class": "stocks",
            "value_minor_units": 1000,
            "currency": "USD",
        },
        headers=auth_headers,
    )
    assert create_resp.status_code == 201

    resp = await client.get(
        "/v1/admin/investments/holdings",
        params={"tenant_id": other_tenant_id},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []
