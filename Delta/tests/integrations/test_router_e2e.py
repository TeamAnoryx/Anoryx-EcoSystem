"""D-019 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB. Drives a full
sync-and-reconcile flow over HTTP: D-014 vendor/PO -> D-019 register system -> run
sync -> list line items -> reconciliation report."""

from __future__ import annotations

from .conftest import db_required


@db_required
async def test_systems_endpoint_401_without_bearer(client) -> None:
    resp = await client.get(
        "/v1/admin/integrations/systems?tenant_id=11111111-1111-4111-8111-111111111111"
    )
    assert resp.status_code == 401


@db_required
async def test_full_sync_flow_over_http(client, auth_headers, tenant_id) -> None:
    vendor_resp = await client.post(
        "/v1/admin/erp/vendors",
        json={"tenant_id": tenant_id, "name": "Acme Supplies"},
        headers=auth_headers,
    )
    assert vendor_resp.status_code == 201
    vendor_id = vendor_resp.json()["vendor_id"]

    po_resp = await client.post(
        "/v1/admin/erp/purchase-orders",
        json={
            "tenant_id": tenant_id,
            "vendor_id": vendor_id,
            "description": "Q1 consulting services",
            "amount_minor_units": 100_000,
            "requested_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert po_resp.status_code == 201
    po_id = po_resp.json()["po_id"]

    decision_resp = await client.post(
        f"/v1/admin/erp/purchase-orders/{po_id}/decision",
        json={"tenant_id": tenant_id, "action": "approve", "actor": "Bob Smith"},
        headers=auth_headers,
    )
    assert decision_resp.status_code == 200

    system_resp = await client.post(
        "/v1/admin/integrations/systems",
        json={
            "tenant_id": tenant_id,
            "name": "Corp NetSuite",
            "system_type": "corporate_erp",
            "vendor_label": "NetSuite",
        },
        headers=auth_headers,
    )
    assert system_resp.status_code == 201
    system = system_resp.json()
    assert system["status"] == "active"
    system_id = system["system_id"]

    sync_resp = await client.post(
        f"/v1/admin/integrations/systems/{system_id}/sync",
        json={
            "tenant_id": tenant_id,
            "triggered_by": "ops@example.com",
            "line_items": [
                {
                    "external_reference": "NETSUITE-PO-1",
                    "amount_minor_units": 100_000,
                    "currency": "USD",
                    "po_id": po_id,
                },
                {
                    "external_reference": "UNKNOWN-CLOUD-CHARGE",
                    "amount_minor_units": 750,
                    "currency": "USD",
                },
            ],
        },
        headers=auth_headers,
    )
    assert sync_resp.status_code == 201
    run = sync_resp.json()
    assert run["records_ingested"] == 2
    assert run["records_matched"] == 1
    assert run["records_unreconciled"] == 1
    sync_run_id = run["sync_run_id"]

    runs_resp = await client.get(
        f"/v1/admin/integrations/systems/{system_id}/sync-runs?tenant_id={tenant_id}",
        headers=auth_headers,
    )
    assert runs_resp.status_code == 200
    assert len(runs_resp.json()) == 1

    line_items_resp = await client.get(
        f"/v1/admin/integrations/sync-runs/{sync_run_id}/line-items?tenant_id={tenant_id}",
        headers=auth_headers,
    )
    assert line_items_resp.status_code == 200
    items = line_items_resp.json()
    assert len(items) == 2
    statuses = {item["matched_status"] for item in items}
    assert statuses == {"matched", "unreconciled"}

    reconciliation_resp = await client.get(
        f"/v1/admin/integrations/systems/{system_id}/reconciliation?tenant_id={tenant_id}",
        headers=auth_headers,
    )
    assert reconciliation_resp.status_code == 200
    report = reconciliation_resp.json()
    assert report["total_runs"] == 1
    assert report["matched_count"] == 1
    assert report["unreconciled_count"] == 1


@db_required
async def test_sync_against_missing_system_returns_404(client, auth_headers, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/integrations/systems/99999999-9999-4999-8999-999999999999/sync",
        json={
            "tenant_id": tenant_id,
            "triggered_by": "ops@example.com",
            "line_items": [
                {"external_reference": "X", "amount_minor_units": 100, "currency": "USD"}
            ],
        },
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_cross_tenant_system_list_isolated_over_http(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    create_resp = await client.post(
        "/v1/admin/integrations/systems",
        json={
            "tenant_id": tenant_id,
            "name": "Tenant A's System",
            "system_type": "cloud_cost",
            "vendor_label": "AWS",
        },
        headers=auth_headers,
    )
    assert create_resp.status_code == 201

    resp = await client.get(
        f"/v1/admin/integrations/systems?tenant_id={other_tenant_id}", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json() == []
