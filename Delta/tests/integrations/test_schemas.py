"""D-019 pure schema validation (no DB). Mirrors ``tests/invoicing/test_schemas.py``'s shape."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from delta.integrations.schemas import (
    ExternalSystemCreateRequest,
    SyncLineItemInput,
    SyncRunCreateRequest,
)

_TENANT = str(uuid.uuid4())
_PO = str(uuid.uuid4())
_INVOICE = str(uuid.uuid4())


def test_external_system_create_request_accepts_valid_payload() -> None:
    req = ExternalSystemCreateRequest(
        tenant_id=_TENANT,
        name="Corp NetSuite",
        system_type="corporate_erp",
        vendor_label="NetSuite",
    )
    assert req.system_type == "corporate_erp"


def test_external_system_create_request_rejects_unknown_system_type() -> None:
    with pytest.raises(ValidationError):
        ExternalSystemCreateRequest(
            tenant_id=_TENANT, name="X", system_type="bogus", vendor_label="X"
        )


def test_external_system_create_request_rejects_control_chars_in_name() -> None:
    with pytest.raises(ValidationError):
        ExternalSystemCreateRequest(
            tenant_id=_TENANT,
            name="Corp\nNetSuite",
            system_type="corporate_erp",
            vendor_label="NetSuite",
        )


def test_external_system_create_request_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        ExternalSystemCreateRequest(
            tenant_id=_TENANT,
            name="X",
            system_type="corporate_erp",
            vendor_label="X",
            unexpected="nope",
        )


def test_sync_line_item_input_accepts_po_reference() -> None:
    item = SyncLineItemInput(
        external_reference="EXT-1", amount_minor_units=1000, currency="USD", po_id=_PO
    )
    assert item.po_id == _PO
    assert item.invoice_id is None


def test_sync_line_item_input_accepts_no_reference() -> None:
    item = SyncLineItemInput(external_reference="EXT-1", amount_minor_units=1000, currency="USD")
    assert item.po_id is None
    assert item.invoice_id is None


def test_sync_line_item_input_rejects_both_references() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(
            external_reference="EXT-1",
            amount_minor_units=1000,
            currency="USD",
            po_id=_PO,
            invoice_id=_INVOICE,
        )


def test_sync_line_item_input_rejects_float_amount() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(external_reference="EXT-1", amount_minor_units=1000.5, currency="USD")


def test_sync_line_item_input_rejects_negative_amount() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(external_reference="EXT-1", amount_minor_units=-1, currency="USD")


def test_sync_line_item_input_rejects_control_chars_in_reference() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(
            external_reference="EXT-1\nX-Injected: true", amount_minor_units=1000, currency="USD"
        )


def _valid_line_item() -> dict:
    return {"external_reference": "EXT-1", "amount_minor_units": 1000, "currency": "USD"}


def test_sync_run_create_request_accepts_valid_payload() -> None:
    req = SyncRunCreateRequest(
        tenant_id=_TENANT, triggered_by="ops@example.com", line_items=[_valid_line_item()]
    )
    assert len(req.line_items) == 1


def test_sync_run_create_request_rejects_empty_line_items() -> None:
    with pytest.raises(ValidationError):
        SyncRunCreateRequest(tenant_id=_TENANT, triggered_by="ops@example.com", line_items=[])


def test_sync_run_create_request_rejects_too_many_line_items() -> None:
    with pytest.raises(ValidationError):
        SyncRunCreateRequest(
            tenant_id=_TENANT,
            triggered_by="ops@example.com",
            line_items=[_valid_line_item()] * 501,
        )


def test_sync_run_create_request_rejects_control_chars_in_triggered_by() -> None:
    with pytest.raises(ValidationError):
        SyncRunCreateRequest(
            tenant_id=_TENANT, triggered_by="ops\x00", line_items=[_valid_line_item()]
        )


def test_sync_run_create_request_rejects_control_chars_in_note() -> None:
    with pytest.raises(ValidationError):
        SyncRunCreateRequest(
            tenant_id=_TENANT,
            triggered_by="ops@example.com",
            note="bad\x1b[31m",
            line_items=[_valid_line_item()],
        )
