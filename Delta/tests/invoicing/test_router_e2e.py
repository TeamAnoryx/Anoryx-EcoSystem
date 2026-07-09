"""D-018 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB. Drives the
full three-way match over HTTP: D-014 vendor/PO -> D-015 task (milestone) -> D-018
invoice submit/decide/pay -> reconciliation report."""

from __future__ import annotations

from .conftest import db_required


async def _seed_vendor_and_approved_po(client, auth_headers, tenant_id, *, amount=100_000):
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
            "amount_minor_units": amount,
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
    return vendor_id, po_id


@db_required
async def test_invoices_endpoint_401_without_bearer(client) -> None:
    resp = await client.get(
        "/v1/admin/invoicing/invoices?tenant_id=11111111-1111-4111-8111-111111111111"
    )
    assert resp.status_code == 401


@db_required
async def test_full_invoicing_flow_over_http(client, auth_headers, tenant_id) -> None:
    vendor_id, po_id = await _seed_vendor_and_approved_po(
        client, auth_headers, tenant_id, amount=100_000
    )

    task_resp = await client.post(
        "/v1/admin/pm/tasks",
        json={
            "tenant_id": tenant_id,
            "project_id": "11111111-1111-4111-8111-111111111111",
            "title": "Deliver Q1 milestone",
        },
        headers=auth_headers,
    )
    assert task_resp.status_code == 201
    task_id = task_resp.json()["task_id"]

    task_status_resp = await client.post(
        f"/v1/admin/pm/tasks/{task_id}/status",
        json={"tenant_id": tenant_id, "status": "done"},
        headers=auth_headers,
    )
    assert task_status_resp.status_code == 200
    assert task_status_resp.json()["status"] == "done"

    invoice_resp = await client.post(
        "/v1/admin/invoicing/invoices",
        json={
            "tenant_id": tenant_id,
            "vendor_id": vendor_id,
            "po_id": po_id,
            "milestone_task_id": task_id,
            "invoice_number": "INV-1001",
            "description": "Q1 milestone delivered",
            "amount_minor_units": 60_000,
            "submitted_by": "vendor-ap@acme.example",
        },
        headers=auth_headers,
    )
    assert invoice_resp.status_code == 201
    invoice = invoice_resp.json()
    assert invoice["status"] == "submitted"
    assert invoice["milestone_task_id"] == task_id
    invoice_id = invoice["invoice_id"]

    decide_resp = await client.post(
        f"/v1/admin/invoicing/invoices/{invoice_id}/decision",
        json={"tenant_id": tenant_id, "action": "approve", "actor": "ap-lead@example.com"},
        headers=auth_headers,
    )
    assert decide_resp.status_code == 200
    assert decide_resp.json()["status"] == "approved"

    # Already-decided invoice: a second decision is rejected.
    repeat_decide_resp = await client.post(
        f"/v1/admin/invoicing/invoices/{invoice_id}/decision",
        json={"tenant_id": tenant_id, "action": "dispute", "actor": "ap-lead@example.com"},
        headers=auth_headers,
    )
    assert repeat_decide_resp.status_code == 409

    payment_resp = await client.post(
        f"/v1/admin/invoicing/invoices/{invoice_id}/payments",
        json={
            "tenant_id": tenant_id,
            "amount_minor_units": 20_000,
            "paid_at": "2026-07-09T12:00:00Z",
            "recorded_by": "treasury@example.com",
        },
        headers=auth_headers,
    )
    assert payment_resp.status_code == 201

    # Overpayment beyond the remaining balance is rejected.
    overpay_resp = await client.post(
        f"/v1/admin/invoicing/invoices/{invoice_id}/payments",
        json={
            "tenant_id": tenant_id,
            "amount_minor_units": 40_001,
            "paid_at": "2026-07-09T12:05:00Z",
            "recorded_by": "treasury@example.com",
        },
        headers=auth_headers,
    )
    assert overpay_resp.status_code == 422

    final_payment_resp = await client.post(
        f"/v1/admin/invoicing/invoices/{invoice_id}/payments",
        json={
            "tenant_id": tenant_id,
            "amount_minor_units": 40_000,
            "paid_at": "2026-07-09T12:10:00Z",
            "recorded_by": "treasury@example.com",
        },
        headers=auth_headers,
    )
    assert final_payment_resp.status_code == 201

    invoices_resp = await client.get(
        f"/v1/admin/invoicing/invoices?tenant_id={tenant_id}&po_id={po_id}", headers=auth_headers
    )
    assert invoices_resp.status_code == 200
    listed = invoices_resp.json()
    assert len(listed) == 1
    assert listed[0]["status"] == "paid"
    assert listed[0]["amount_paid_minor_units"] == 60_000

    payments_resp = await client.get(
        f"/v1/admin/invoicing/invoices/{invoice_id}/payments?tenant_id={tenant_id}",
        headers=auth_headers,
    )
    assert payments_resp.status_code == 200
    assert len(payments_resp.json()) == 2

    reconciliation_resp = await client.get(
        f"/v1/admin/invoicing/reconciliation?tenant_id={tenant_id}&vendor_id={vendor_id}",
        headers=auth_headers,
    )
    assert reconciliation_resp.status_code == 200
    report = reconciliation_resp.json()
    assert report["committed_minor_units"] == 100_000
    assert report["invoiced_minor_units"] == 60_000
    assert report["paid_minor_units"] == 60_000
    assert report["outstanding_minor_units"] == 0
    assert report["over_invoiced"] is False
    assert report["over_paid"] is False


@db_required
async def test_invoice_against_missing_vendor_returns_404(client, auth_headers, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/invoicing/invoices",
        json={
            "tenant_id": tenant_id,
            "vendor_id": "99999999-9999-4999-8999-999999999999",
            "po_id": "88888888-8888-4888-8888-888888888888",
            "invoice_number": "INV-GHOST",
            "description": "Ghost invoice",
            "amount_minor_units": 1000,
            "submitted_by": "vendor-ap@example.com",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_invoice_exceeding_po_amount_returns_422(client, auth_headers, tenant_id) -> None:
    vendor_id, po_id = await _seed_vendor_and_approved_po(
        client, auth_headers, tenant_id, amount=10_000
    )
    resp = await client.post(
        "/v1/admin/invoicing/invoices",
        json={
            "tenant_id": tenant_id,
            "vendor_id": vendor_id,
            "po_id": po_id,
            "invoice_number": "INV-2001",
            "description": "Over the committed amount",
            "amount_minor_units": 10_001,
            "submitted_by": "vendor-ap@example.com",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_cross_tenant_invoice_list_isolated_over_http(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    vendor_id, po_id = await _seed_vendor_and_approved_po(client, auth_headers, tenant_id)
    invoice_resp = await client.post(
        "/v1/admin/invoicing/invoices",
        json={
            "tenant_id": tenant_id,
            "vendor_id": vendor_id,
            "po_id": po_id,
            "invoice_number": "INV-3001",
            "description": "Tenant A's invoice",
            "amount_minor_units": 5_000,
            "submitted_by": "vendor-ap@example.com",
        },
        headers=auth_headers,
    )
    assert invoice_resp.status_code == 201

    resp = await client.get(
        f"/v1/admin/invoicing/invoices?tenant_id={other_tenant_id}", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json() == []
