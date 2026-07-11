"""D-025 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB."""

from __future__ import annotations

from datetime import datetime, timezone

from .conftest import db_required


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _make_account(client, auth_headers, tenant_id: str) -> str:
    resp = await client.post(
        "/v1/admin/personal-finance/accounts",
        json={"tenant_id": tenant_id, "type": "checking", "currency": "USD", "name": "Main"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    return resp.json()["account_id"]


async def _make_source(client, auth_headers, tenant_id: str, account_id: str) -> str:
    resp = await client.post(
        "/v1/admin/bank-imports/sources",
        json={
            "tenant_id": tenant_id,
            "account_id": account_id,
            "institution_label": "Test Bank",
            "created_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 201
    return resp.json()["source_id"]


def _line(ref: str, **overrides) -> dict:
    payload = {
        "external_reference": ref,
        "amount_minor_units": -1250,
        "currency": "USD",
        "occurred_at": _iso_now(),
        "category": "dining",
    }
    payload.update(overrides)
    return payload


@db_required
async def test_sources_endpoint_401_without_bearer(client, tenant_id) -> None:
    resp = await client.get(f"/v1/admin/bank-imports/sources?tenant_id={tenant_id}")
    assert resp.status_code == 401


@db_required
async def test_full_import_flow_over_http(client, auth_headers, tenant_id) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id)
    source_id = await _make_source(client, auth_headers, tenant_id, account_id)

    import_resp = await client.post(
        f"/v1/admin/bank-imports/sources/{source_id}/import",
        json={
            "tenant_id": tenant_id,
            "imported_by": "Jane Doe",
            "lines": [
                _line("ref-1"),
                _line("ref-2", amount_minor_units=250_000, category="income"),
            ],
        },
        headers=auth_headers,
    )
    assert import_resp.status_code == 201
    body = import_resp.json()
    assert body["records_imported"] == 2
    assert body["records_supplied"] == 2

    # Imported spend is visible in D-021's own ledger over HTTP, source-tagged.
    txns_resp = await client.get(
        f"/v1/admin/personal-finance/transactions?tenant_id={tenant_id}&account_id={account_id}",
        headers=auth_headers,
    )
    assert txns_resp.status_code == 200
    txns = txns_resp.json()
    assert len(txns) == 2
    assert all(t["source"] == "import" for t in txns)

    # Re-importing the same statement dedups over HTTP too.
    reimport_resp = await client.post(
        f"/v1/admin/bank-imports/sources/{source_id}/import",
        json={"tenant_id": tenant_id, "imported_by": "Jane Doe", "lines": [_line("ref-1")]},
        headers=auth_headers,
    )
    assert reimport_resp.status_code == 201
    assert reimport_resp.json()["records_skipped_duplicate"] == 1

    imports_resp = await client.get(
        f"/v1/admin/bank-imports/imports?tenant_id={tenant_id}&source_id={source_id}",
        headers=auth_headers,
    )
    assert imports_resp.status_code == 200
    assert len(imports_resp.json()) == 2


@db_required
async def test_register_source_missing_account_404(client, auth_headers, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/bank-imports/sources",
        json={
            "tenant_id": tenant_id,
            "account_id": "99999999-9999-4999-8999-999999999999",
            "institution_label": "Ghost Bank",
            "created_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_import_into_unknown_source_404(client, auth_headers, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/bank-imports/sources/99999999-9999-4999-8999-999999999999/import",
        json={"tenant_id": tenant_id, "imported_by": "Jane Doe", "lines": [_line("ref-1")]},
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_card_number_like_merchant_422_over_http(client, auth_headers, tenant_id) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id)
    source_id = await _make_source(client, auth_headers, tenant_id, account_id)
    resp = await client.post(
        f"/v1/admin/bank-imports/sources/{source_id}/import",
        json={
            "tenant_id": tenant_id,
            "imported_by": "Jane Doe",
            "lines": [_line("ref-1", merchant="VISA 4111 1111 1111 1111")],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_cross_tenant_sources_list_isolated(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    account_id = await _make_account(client, auth_headers, tenant_id)
    await _make_source(client, auth_headers, tenant_id, account_id)

    resp = await client.get(
        f"/v1/admin/bank-imports/sources?tenant_id={other_tenant_id}", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json() == []
