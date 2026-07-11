"""D-025 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB."""

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


def _link_payload(tenant_id: str, account_id: str, **overrides) -> dict:
    payload = {
        "tenant_id": tenant_id,
        "account_id": account_id,
        "institution_name": "First Bank",
        "masked_account_last4": "1234",
        "consent_confirmed": True,
        "requested_by": "Jane Doe",
    }
    payload.update(overrides)
    return payload


def _sync_payload(tenant_id: str, items: list[dict], **overrides) -> dict:
    payload = {"tenant_id": tenant_id, "triggered_by": "cron", "line_items": items}
    payload.update(overrides)
    return payload


def _item(**overrides) -> dict:
    payload = {
        "external_reference": "bank-txn-1",
        "category": "groceries",
        "amount_minor_units": -500,
        "currency": "USD",
        "occurred_at": "2026-07-01T00:00:00Z",
    }
    payload.update(overrides)
    return payload


@db_required
async def test_create_link_endpoint_401_without_bearer(client, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/bank-aggregation/links",
        json=_link_payload(tenant_id, "22222222-2222-4222-8222-222222222222"),
    )
    assert resp.status_code == 401


@db_required
async def test_full_link_and_sync_flow_over_http(client, auth_headers, tenant_id) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id)

    link_resp = await client.post(
        "/v1/admin/bank-aggregation/links",
        json=_link_payload(tenant_id, account_id),
        headers=auth_headers,
    )
    assert link_resp.status_code == 201
    link = link_resp.json()
    assert link["status"] == "linked"
    link_id = link["link_id"]

    sync_resp = await client.post(
        f"/v1/admin/bank-aggregation/links/{link_id}/sync",
        json=_sync_payload(tenant_id, [_item()]),
        headers=auth_headers,
    )
    assert sync_resp.status_code == 201
    run = sync_resp.json()
    assert run["records_written"] == 1
    assert run["records_deduplicated"] == 0
    assert run["records_rejected"] == 0

    # The ingested transaction is visible in D-021's own ledger over HTTP.
    txns_resp = await client.get(
        f"/v1/admin/personal-finance/transactions?tenant_id={tenant_id}&account_id={account_id}",
        headers=auth_headers,
    )
    assert txns_resp.status_code == 200
    txns = txns_resp.json()
    assert len(txns) == 1
    assert txns[0]["amount_minor_units"] == -500
    assert txns[0]["source"] == "aggregated"

    # A retried sync with the same external_reference is deduplicated, not re-written.
    replay_resp = await client.post(
        f"/v1/admin/bank-aggregation/links/{link_id}/sync",
        json=_sync_payload(tenant_id, [_item()]),
        headers=auth_headers,
    )
    assert replay_resp.status_code == 201
    replay = replay_resp.json()
    assert replay["records_written"] == 0
    assert replay["records_deduplicated"] == 1

    sync_runs_resp = await client.get(
        f"/v1/admin/bank-aggregation/links/{link_id}/sync-runs?tenant_id={tenant_id}",
        headers=auth_headers,
    )
    assert sync_runs_resp.status_code == 200
    assert len(sync_runs_resp.json()) == 2

    # Revoke, then a further sync is rejected.
    revoke_resp = await client.post(
        f"/v1/admin/bank-aggregation/links/{link_id}/revoke",
        json={"tenant_id": tenant_id, "requested_by": "Jane Doe"},
        headers=auth_headers,
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "revoked"

    blocked_resp = await client.post(
        f"/v1/admin/bank-aggregation/links/{link_id}/sync",
        json=_sync_payload(tenant_id, [_item(external_reference="bank-txn-2")]),
        headers=auth_headers,
    )
    assert blocked_resp.status_code == 409


@db_required
async def test_masked_account_last4_rejects_non_four_digit_over_http(
    client, auth_headers, tenant_id
) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id)
    resp = await client.post(
        "/v1/admin/bank-aggregation/links",
        json=_link_payload(tenant_id, account_id, masked_account_last4="123456789012"),
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_link_unknown_account_404_over_http(client, auth_headers, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/bank-aggregation/links",
        json=_link_payload(tenant_id, "99999999-9999-4999-8999-999999999999"),
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_link_already_linked_account_409_over_http(client, auth_headers, tenant_id) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id)
    first = await client.post(
        "/v1/admin/bank-aggregation/links",
        json=_link_payload(tenant_id, account_id),
        headers=auth_headers,
    )
    assert first.status_code == 201

    second = await client.post(
        "/v1/admin/bank-aggregation/links",
        json=_link_payload(tenant_id, account_id),
        headers=auth_headers,
    )
    assert second.status_code == 409


@db_required
async def test_sync_currency_mismatch_rejected_not_500_over_http(
    client, auth_headers, tenant_id
) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id, currency="USD")
    link_resp = await client.post(
        "/v1/admin/bank-aggregation/links",
        json=_link_payload(tenant_id, account_id),
        headers=auth_headers,
    )
    link_id = link_resp.json()["link_id"]

    resp = await client.post(
        f"/v1/admin/bank-aggregation/links/{link_id}/sync",
        json=_sync_payload(tenant_id, [_item(currency="EUR")]),
        headers=auth_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["records_written"] == 0
    assert body["records_rejected"] == 1


@db_required
async def test_cross_tenant_links_isolated_over_http(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id)
    await client.post(
        "/v1/admin/bank-aggregation/links",
        json=_link_payload(tenant_id, account_id),
        headers=auth_headers,
    )

    resp = await client.get(
        f"/v1/admin/bank-aggregation/links?tenant_id={other_tenant_id}", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json() == []

    # A cross-tenant link attempt against tenant A's account is a 404 (no existence
    # leak, no side effects).
    probe = await client.post(
        "/v1/admin/bank-aggregation/links",
        json=_link_payload(other_tenant_id, account_id),
        headers=auth_headers,
    )
    assert probe.status_code == 404
