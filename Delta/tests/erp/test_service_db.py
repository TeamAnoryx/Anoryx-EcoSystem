"""D-014 service-layer DB tests: exception mapping, forward-only asset lifecycle, and
the D-009 audit-chain wiring on purchase-order decisions.

Each mutating service call commits — a new ``get_tenant_session`` block is opened per
commit, never reused across two writes (same discipline as ``tests/crm/test_service_db.py``).
"""

from __future__ import annotations

import pytest

from delta.erp.schemas import (
    AssetCreateRequest,
    AssetStatusTransitionRequest,
    PurchaseOrderCreateRequest,
    PurchaseOrderDecisionRequest,
    VendorCreateRequest,
)
from delta.erp.service import (
    AssetNotFoundError,
    InvalidAssetTransitionError,
    PurchaseOrderAlreadyDecidedError,
    PurchaseOrderNotFoundError,
    VendorNotFoundError,
    create_asset,
    create_purchase_order,
    create_vendor,
    decide_purchase_order,
    transition_asset_status,
)
from delta.persistence.audit_log import list_history
from delta.persistence.database import get_tenant_session

from .conftest import db_required


@db_required
async def test_create_asset_with_cost_defaults_currency_when_null(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        asset = await create_asset(
            session,
            AssetCreateRequest(
                tenant_id=tenant_id,
                name="Laptop",
                category="equipment",
                acquisition_cost_minor_units=150_000,
                currency=None,
            ),
        )
    assert asset.acquisition_cost_minor_units == 150_000
    assert asset.currency == "USD"


@db_required
async def test_create_purchase_order_against_missing_vendor_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(VendorNotFoundError):
            await create_purchase_order(
                session,
                PurchaseOrderCreateRequest(
                    tenant_id=tenant_id,
                    vendor_id="99999999-9999-4999-8999-999999999999",
                    description="Ghost PO",
                    amount_minor_units=1000,
                    requested_by="Jane",
                ),
            )


@db_required
async def test_create_purchase_order_against_missing_asset_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor = await create_vendor(session, VendorCreateRequest(tenant_id=tenant_id, name="Acme"))

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(AssetNotFoundError):
            await create_purchase_order(
                session,
                PurchaseOrderCreateRequest(
                    tenant_id=tenant_id,
                    vendor_id=vendor.vendor_id,
                    asset_id="99999999-9999-4999-8999-999999999999",
                    description="Ghost asset PO",
                    amount_minor_units=1000,
                    requested_by="Jane",
                ),
            )


@db_required
async def test_transition_asset_status_to_active_rejected(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        asset = await create_asset(
            session, AssetCreateRequest(tenant_id=tenant_id, name="Laptop", category="equipment")
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(InvalidAssetTransitionError):
            await transition_asset_status(
                session,
                asset_id=asset.asset_id,
                req=AssetStatusTransitionRequest(
                    tenant_id=tenant_id, status="active", actor="Jane"
                ),
            )


@db_required
async def test_transition_asset_status_skipping_a_step_rejected(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        asset = await create_asset(
            session, AssetCreateRequest(tenant_id=tenant_id, name="Laptop", category="equipment")
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(InvalidAssetTransitionError):
            await transition_asset_status(
                session,
                asset_id=asset.asset_id,
                req=AssetStatusTransitionRequest(
                    tenant_id=tenant_id, status="disposed", actor="Jane"
                ),
            )


@db_required
async def test_decide_purchase_order_already_decided_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor = await create_vendor(session, VendorCreateRequest(tenant_id=tenant_id, name="Acme"))

    async with get_tenant_session(tenant_id) as session:
        po = await create_purchase_order(
            session,
            PurchaseOrderCreateRequest(
                tenant_id=tenant_id,
                vendor_id=vendor.vendor_id,
                description="Office chairs",
                amount_minor_units=50_000,
                requested_by="Jane",
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        await decide_purchase_order(
            session,
            po_id=po.po_id,
            decision=PurchaseOrderDecisionRequest(
                tenant_id=tenant_id, action="approve", actor="Bob"
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(PurchaseOrderAlreadyDecidedError):
            await decide_purchase_order(
                session,
                po_id=po.po_id,
                decision=PurchaseOrderDecisionRequest(
                    tenant_id=tenant_id, action="reject", actor="Bob"
                ),
            )


@db_required
async def test_decide_purchase_order_missing_po_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(PurchaseOrderNotFoundError):
            await decide_purchase_order(
                session,
                po_id="99999999-9999-4999-8999-999999999999",
                decision=PurchaseOrderDecisionRequest(
                    tenant_id=tenant_id, action="approve", actor="Bob"
                ),
            )


@db_required
async def test_purchase_order_decision_lands_in_d009_audit_chain(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        vendor = await create_vendor(session, VendorCreateRequest(tenant_id=tenant_id, name="Acme"))

    async with get_tenant_session(tenant_id) as session:
        po = await create_purchase_order(
            session,
            PurchaseOrderCreateRequest(
                tenant_id=tenant_id,
                vendor_id=vendor.vendor_id,
                description="Office chairs",
                amount_minor_units=50_000,
                requested_by="Jane",
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        await decide_purchase_order(
            session,
            po_id=po.po_id,
            decision=PurchaseOrderDecisionRequest(
                tenant_id=tenant_id, action="approve", actor="Bob"
            ),
        )

    async with get_tenant_session(tenant_id) as session:
        rows = await list_history(session, entity_type="purchase_order", entity_id=po.po_id)

    actions = {r.action for r in rows}
    assert actions == {"requested", "approved"}
