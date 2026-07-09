"""D-014 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB."""

from __future__ import annotations

from .conftest import db_required


@db_required
async def test_vendors_endpoint_401_without_bearer(client) -> None:
    resp = await client.get("/v1/admin/erp/vendors?tenant_id=11111111-1111-4111-8111-111111111111")
    assert resp.status_code == 401


@db_required
async def test_full_procurement_flow_over_http(client, auth_headers, tenant_id) -> None:
    vendor_resp = await client.post(
        "/v1/admin/erp/vendors",
        json={"tenant_id": tenant_id, "name": "Acme Supplies"},
        headers=auth_headers,
    )
    assert vendor_resp.status_code == 201
    vendor_id = vendor_resp.json()["vendor_id"]

    asset_resp = await client.post(
        "/v1/admin/erp/assets",
        json={
            "tenant_id": tenant_id,
            "name": "Laptop",
            "category": "equipment",
            "acquisition_cost_minor_units": 150_000,
        },
        headers=auth_headers,
    )
    assert asset_resp.status_code == 201
    asset = asset_resp.json()
    assert asset["status"] == "active"

    po_resp = await client.post(
        "/v1/admin/erp/purchase-orders",
        json={
            "tenant_id": tenant_id,
            "vendor_id": vendor_id,
            "asset_id": asset["asset_id"],
            "description": "New engineering laptop",
            "amount_minor_units": 150_000,
            "requested_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert po_resp.status_code == 201
    po = po_resp.json()
    assert po["status"] == "requested"

    decision_resp = await client.post(
        f"/v1/admin/erp/purchase-orders/{po['po_id']}/decision",
        json={"tenant_id": tenant_id, "action": "approve", "actor": "Bob Smith"},
        headers=auth_headers,
    )
    assert decision_resp.status_code == 200
    assert decision_resp.json()["status"] == "approved"

    # Already-decided PO: a second decision is rejected.
    repeat_resp = await client.post(
        f"/v1/admin/erp/purchase-orders/{po['po_id']}/decision",
        json={"tenant_id": tenant_id, "action": "reject", "actor": "Bob Smith"},
        headers=auth_headers,
    )
    assert repeat_resp.status_code == 409

    # Asset lifecycle: active -> retired succeeds, then retired -> retired is rejected.
    retire_resp = await client.post(
        f"/v1/admin/erp/assets/{asset['asset_id']}/status",
        json={"tenant_id": tenant_id, "status": "retired", "actor": "Bob Smith"},
        headers=auth_headers,
    )
    assert retire_resp.status_code == 200
    assert retire_resp.json()["status"] == "retired"

    repeat_retire_resp = await client.post(
        f"/v1/admin/erp/assets/{asset['asset_id']}/status",
        json={"tenant_id": tenant_id, "status": "retired", "actor": "Bob Smith"},
        headers=auth_headers,
    )
    assert repeat_retire_resp.status_code == 409

    vendors_resp = await client.get(
        f"/v1/admin/erp/vendors?tenant_id={tenant_id}", headers=auth_headers
    )
    assert vendors_resp.status_code == 200
    assert len(vendors_resp.json()) == 1


@db_required
async def test_purchase_order_against_missing_vendor_returns_404(
    client, auth_headers, tenant_id
) -> None:
    resp = await client.post(
        "/v1/admin/erp/purchase-orders",
        json={
            "tenant_id": tenant_id,
            "vendor_id": "99999999-9999-4999-8999-999999999999",
            "description": "Ghost PO",
            "amount_minor_units": 1000,
            "requested_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_asset_status_skip_step_returns_409(client, auth_headers, tenant_id) -> None:
    asset_resp = await client.post(
        "/v1/admin/erp/assets",
        json={"tenant_id": tenant_id, "name": "Laptop", "category": "equipment"},
        headers=auth_headers,
    )
    asset_id = asset_resp.json()["asset_id"]

    resp = await client.post(
        f"/v1/admin/erp/assets/{asset_id}/status",
        json={"tenant_id": tenant_id, "status": "disposed", "actor": "Jane Doe"},
        headers=auth_headers,
    )
    assert resp.status_code == 409


@db_required
async def test_cross_tenant_vendor_list_isolated_over_http(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    await client.post(
        "/v1/admin/erp/vendors",
        json={"tenant_id": tenant_id, "name": "Tenant A's Vendor"},
        headers=auth_headers,
    )

    resp = await client.get(
        f"/v1/admin/erp/vendors?tenant_id={other_tenant_id}", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json() == []
