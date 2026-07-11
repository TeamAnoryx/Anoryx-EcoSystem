"""D-024 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB."""

from __future__ import annotations

from .conftest import db_required


async def _make_account(client, auth_headers, tenant_id: str, *, currency: str = "USD") -> str:
    resp = await client.post(
        "/v1/admin/personal-finance/accounts",
        json={"tenant_id": tenant_id, "type": "checking", "currency": currency, "name": "Main"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    return resp.json()["account_id"]


def _payload(tenant_id: str, account_id: str, key: str, **overrides) -> dict:
    payload = {
        "tenant_id": tenant_id,
        "account_id": account_id,
        "idempotency_key": key,
        "amount_minor_units": 500,
        "currency": "USD",
        "category": "dining",
        "requested_by": "Jane Doe",
    }
    payload.update(overrides)
    return payload


@db_required
async def test_execute_endpoint_401_without_bearer(client, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/micro-transactions/execute",
        json=_payload(tenant_id, "22222222-2222-4222-8222-222222222222", "k-1"),
    )
    assert resp.status_code == 401


@db_required
async def test_full_execution_flow_over_http(client, auth_headers, tenant_id) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id)

    exec_resp = await client.post(
        "/v1/admin/micro-transactions/execute",
        json=_payload(tenant_id, account_id, "k-1", amount_minor_units=750),
        headers=auth_headers,
    )
    assert exec_resp.status_code == 201
    body = exec_resp.json()
    assert body["status"] == "executed"
    assert body["txn_id"] is not None
    assert body["idempotent_replay"] is False

    # The executed spend is visible in D-021's own ledger over HTTP.
    txns_resp = await client.get(
        f"/v1/admin/personal-finance/transactions?tenant_id={tenant_id}&account_id={account_id}",
        headers=auth_headers,
    )
    assert txns_resp.status_code == 200
    txns = txns_resp.json()
    assert len(txns) == 1
    assert txns[0]["amount_minor_units"] == -750
    assert txns[0]["source"] == "execution"

    # Replay: same key, same stored outcome, marked as a replay.
    replay_resp = await client.post(
        "/v1/admin/micro-transactions/execute",
        json=_payload(tenant_id, account_id, "k-1", amount_minor_units=750),
        headers=auth_headers,
    )
    assert replay_resp.status_code == 201
    replay = replay_resp.json()
    assert replay["idempotent_replay"] is True
    assert replay["execution_id"] == body["execution_id"]

    # The execution log lists both nothing extra — one attempt, one row.
    list_resp = await client.get(
        f"/v1/admin/micro-transactions?tenant_id={tenant_id}", headers=auth_headers
    )
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1


@db_required
async def test_amount_above_micro_cap_rejected_422(client, auth_headers, tenant_id) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id)
    resp = await client.post(
        "/v1/admin/micro-transactions/execute",
        json=_payload(tenant_id, account_id, "k-1", amount_minor_units=10_001),
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_unknown_account_404_over_http(client, auth_headers, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/micro-transactions/execute",
        json=_payload(tenant_id, "99999999-9999-4999-8999-999999999999", "k-1"),
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_currency_mismatch_rejection_over_http(client, auth_headers, tenant_id) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id, currency="USD")
    resp = await client.post(
        "/v1/admin/micro-transactions/execute",
        json=_payload(tenant_id, account_id, "k-1", currency="EUR"),
        headers=auth_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "rejected"
    assert body["rejection_reason"] == "currency_mismatch"


@db_required
async def test_cross_tenant_executions_list_isolated(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id)
    await client.post(
        "/v1/admin/micro-transactions/execute",
        json=_payload(tenant_id, account_id, "k-1"),
        headers=auth_headers,
    )

    resp = await client.get(
        f"/v1/admin/micro-transactions?tenant_id={other_tenant_id}", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json() == []

    # A cross-tenant execution attempt against tenant A's account is a 404 (no
    # existence leak, no side effects).
    probe = await client.post(
        "/v1/admin/micro-transactions/execute",
        json=_payload(other_tenant_id, account_id, "k-2"),
        headers=auth_headers,
    )
    assert probe.status_code == 404
