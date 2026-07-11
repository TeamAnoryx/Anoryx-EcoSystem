"""D-021 non-stubbed HTTP e2e: the real ASGI app, real auth, real DB. Drives a full
account -> transaction -> budget -> health-score flow over HTTP."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx

from .conftest import db_required


def _recent_iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


async def test_accounts_endpoint_401_without_bearer(
    client: httpx.AsyncClient, tenant_id: str
) -> None:
    resp = await client.get("/v1/admin/personal-finance/accounts", params={"tenant_id": tenant_id})
    assert resp.status_code == 401


@db_required
async def test_full_budget_tracking_flow_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    account_resp = await client.post(
        "/v1/admin/personal-finance/accounts",
        json={"tenant_id": tenant_id, "type": "checking", "currency": "USD", "name": "Main"},
        headers=auth_headers,
    )
    assert account_resp.status_code == 201, account_resp.text
    account_id = account_resp.json()["account_id"]

    income_resp = await client.post(
        "/v1/admin/personal-finance/transactions",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "category": "income",
            "amount_minor_units": 250_000,
            "currency": "USD",
            "occurred_at": _recent_iso(2),
        },
        headers=auth_headers,
    )
    assert income_resp.status_code == 201, income_resp.text

    expense_resp = await client.post(
        "/v1/admin/personal-finance/transactions",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "category": "groceries",
            "amount_minor_units": -30_000,
            "currency": "USD",
            "occurred_at": _recent_iso(1),
        },
        headers=auth_headers,
    )
    assert expense_resp.status_code == 201, expense_resp.text

    budget_resp = await client.post(
        "/v1/admin/personal-finance/budgets",
        json={
            "tenant_id": tenant_id,
            "category": "groceries",
            "cap_minor_units": 40_000,
            "currency": "USD",
        },
        headers=auth_headers,
    )
    assert budget_resp.status_code == 201, budget_resp.text

    transactions_resp = await client.get(
        "/v1/admin/personal-finance/transactions",
        params={"tenant_id": tenant_id},
        headers=auth_headers,
    )
    assert transactions_resp.status_code == 200
    assert len(transactions_resp.json()) == 2

    now = datetime.now(timezone.utc)
    health_resp = await client.get(
        "/v1/admin/personal-finance/health-score",
        params={
            "tenant_id": tenant_id,
            "start": (now - timedelta(days=7)).isoformat(),
            "end": now.isoformat(),
        },
        headers=auth_headers,
    )
    assert health_resp.status_code == 200, health_resp.text
    health = health_resp.json()
    assert health["total_income_minor_units"] == 250_000
    assert health["total_expense_minor_units"] == 30_000
    assert health["budgets"][0]["over_cap"] is False
    assert health["health_score"] > 0


@db_required
async def test_transaction_against_unknown_account_returns_404(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    resp = await client.post(
        "/v1/admin/personal-finance/transactions",
        json={
            "tenant_id": tenant_id,
            "account_id": "99999999-9999-4999-8999-999999999999",
            "category": "groceries",
            "amount_minor_units": -1000,
            "currency": "USD",
            "occurred_at": _recent_iso(1),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_health_score_rejects_end_before_start_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/v1/admin/personal-finance/health-score",
        params={
            "tenant_id": tenant_id,
            "start": now.isoformat(),
            "end": (now - timedelta(days=1)).isoformat(),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_transactions_list_rejects_naive_start_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    # Security audit finding: a naive datetime compared against a timestamptz column
    # is either misread or 500s — the boundary must 422 instead.
    resp = await client.get(
        "/v1/admin/personal-finance/transactions",
        params={"tenant_id": tenant_id, "start": "2026-01-01T00:00:00"},
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_transactions_list_rejects_end_before_start_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    now = datetime.now(timezone.utc)
    resp = await client.get(
        "/v1/admin/personal-finance/transactions",
        params={
            "tenant_id": tenant_id,
            "start": now.isoformat(),
            "end": (now - timedelta(days=1)).isoformat(),
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_cross_tenant_accounts_isolated_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str, other_tenant_id: str
) -> None:
    create_resp = await client.post(
        "/v1/admin/personal-finance/accounts",
        json={"tenant_id": tenant_id, "type": "savings", "currency": "USD", "name": "Rainy day"},
        headers=auth_headers,
    )
    assert create_resp.status_code == 201

    resp = await client.get(
        "/v1/admin/personal-finance/accounts",
        params={"tenant_id": other_tenant_id},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []
