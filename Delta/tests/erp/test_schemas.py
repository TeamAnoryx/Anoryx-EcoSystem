"""Pure Pydantic validation tests for D-014 ERP schemas — no DB, no I/O."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from delta.erp.schemas import (
    MAX_ASSET_COST_MINOR_UNITS,
    MAX_PO_AMOUNT_MINOR_UNITS,
    AssetCreateRequest,
    AssetStatusTransitionRequest,
    PurchaseOrderCreateRequest,
    PurchaseOrderDecisionRequest,
    VendorCreateRequest,
)

_TENANT = "11111111-1111-4111-8111-111111111111"
_VENDOR = "22222222-2222-4222-8222-222222222222"
_AWARE_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)


def test_vendor_create_accepts_minimal_valid_request() -> None:
    req = VendorCreateRequest(tenant_id=_TENANT, name="Acme Supplies")
    assert req.name == "Acme Supplies"
    assert req.contact_email is None


def test_vendor_create_rejects_control_chars_in_name() -> None:
    with pytest.raises(ValidationError):
        VendorCreateRequest(tenant_id=_TENANT, name="Acme\nSupplies")


def test_vendor_create_rejects_malformed_email() -> None:
    with pytest.raises(ValidationError):
        VendorCreateRequest(tenant_id=_TENANT, name="Acme", contact_email="not-an-email")


def test_vendor_create_accepts_well_formed_email() -> None:
    req = VendorCreateRequest(tenant_id=_TENANT, name="Acme", contact_email="orders@acme.example")
    assert req.contact_email == "orders@acme.example"


def test_vendor_create_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        VendorCreateRequest(tenant_id=_TENANT, name="Acme", unexpected="field")


def test_asset_create_rejects_negative_cost() -> None:
    with pytest.raises(ValidationError):
        AssetCreateRequest(
            tenant_id=_TENANT, name="Laptop", category="equipment", acquisition_cost_minor_units=-1
        )


def test_asset_create_rejects_cost_above_max() -> None:
    with pytest.raises(ValidationError):
        AssetCreateRequest(
            tenant_id=_TENANT,
            name="Laptop",
            category="equipment",
            acquisition_cost_minor_units=MAX_ASSET_COST_MINOR_UNITS + 1,
        )


def test_asset_create_accepts_cost_at_max() -> None:
    req = AssetCreateRequest(
        tenant_id=_TENANT,
        name="Laptop",
        category="equipment",
        acquisition_cost_minor_units=MAX_ASSET_COST_MINOR_UNITS,
    )
    assert req.acquisition_cost_minor_units == MAX_ASSET_COST_MINOR_UNITS


def test_asset_create_rejects_naive_acquired_at() -> None:
    with pytest.raises(ValidationError):
        AssetCreateRequest(
            tenant_id=_TENANT,
            name="Laptop",
            category="equipment",
            acquired_at=datetime(2026, 1, 1),  # naive
        )


def test_asset_create_accepts_aware_acquired_at() -> None:
    req = AssetCreateRequest(
        tenant_id=_TENANT, name="Laptop", category="equipment", acquired_at=_AWARE_NOW
    )
    assert req.acquired_at == _AWARE_NOW


def test_asset_create_rejects_unknown_category() -> None:
    with pytest.raises(ValidationError):
        AssetCreateRequest(tenant_id=_TENANT, name="Laptop", category="spaceship")


def test_asset_status_transition_rejects_control_chars_in_actor() -> None:
    with pytest.raises(ValidationError):
        AssetStatusTransitionRequest(tenant_id=_TENANT, status="retired", actor="Jane\rDoe")


def test_asset_status_transition_rejects_unknown_status() -> None:
    with pytest.raises(ValidationError):
        AssetStatusTransitionRequest(tenant_id=_TENANT, status="lost", actor="Jane Doe")


def test_purchase_order_create_rejects_negative_amount() -> None:
    with pytest.raises(ValidationError):
        PurchaseOrderCreateRequest(
            tenant_id=_TENANT,
            vendor_id=_VENDOR,
            description="Office chairs",
            amount_minor_units=-1,
            requested_by="Jane Doe",
        )


def test_purchase_order_create_rejects_amount_above_max() -> None:
    with pytest.raises(ValidationError):
        PurchaseOrderCreateRequest(
            tenant_id=_TENANT,
            vendor_id=_VENDOR,
            description="Office chairs",
            amount_minor_units=MAX_PO_AMOUNT_MINOR_UNITS + 1,
            requested_by="Jane Doe",
        )


def test_purchase_order_create_accepts_amount_at_max() -> None:
    req = PurchaseOrderCreateRequest(
        tenant_id=_TENANT,
        vendor_id=_VENDOR,
        description="Office chairs",
        amount_minor_units=MAX_PO_AMOUNT_MINOR_UNITS,
        requested_by="Jane Doe",
    )
    assert req.amount_minor_units == MAX_PO_AMOUNT_MINOR_UNITS


def test_purchase_order_create_rejects_control_chars_in_description() -> None:
    with pytest.raises(ValidationError):
        PurchaseOrderCreateRequest(
            tenant_id=_TENANT,
            vendor_id=_VENDOR,
            description="Office\x00chairs",
            amount_minor_units=1000,
            requested_by="Jane Doe",
        )


def test_purchase_order_create_rejects_control_chars_in_requested_by() -> None:
    with pytest.raises(ValidationError):
        PurchaseOrderCreateRequest(
            tenant_id=_TENANT,
            vendor_id=_VENDOR,
            description="Office chairs",
            amount_minor_units=1000,
            requested_by="Jane\nDoe",
        )


def test_purchase_order_decision_rejects_control_chars_in_actor() -> None:
    with pytest.raises(ValidationError):
        PurchaseOrderDecisionRequest(tenant_id=_TENANT, action="approve", actor="Jane\rDoe")


def test_purchase_order_decision_rejects_control_chars_in_note() -> None:
    with pytest.raises(ValidationError):
        PurchaseOrderDecisionRequest(
            tenant_id=_TENANT, action="approve", actor="Jane Doe", note="ok\x00"
        )


def test_purchase_order_decision_rejects_unknown_action() -> None:
    with pytest.raises(ValidationError):
        PurchaseOrderDecisionRequest(tenant_id=_TENANT, action="cancel", actor="Jane Doe")


def test_asset_create_rejects_float_cost() -> None:
    # Security-review finding (ADR-0014 §4): a wire float like 100.0 must be rejected
    # outright, not silently coerced to int by Pydantic's lax mode — the same strict
    # discipline delta.money.Money applies everywhere else.
    with pytest.raises(ValidationError):
        AssetCreateRequest(
            tenant_id=_TENANT,
            name="Laptop",
            category="equipment",
            acquisition_cost_minor_units=100.0,
        )


def test_purchase_order_create_rejects_float_amount() -> None:
    with pytest.raises(ValidationError):
        PurchaseOrderCreateRequest(
            tenant_id=_TENANT,
            vendor_id=_VENDOR,
            description="Office chairs",
            amount_minor_units=1000.0,
            requested_by="Jane Doe",
        )
