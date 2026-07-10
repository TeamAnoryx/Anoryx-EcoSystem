"""D-018 pure schema validation (no DB). Mirrors ``tests/erp/test_schemas.py``'s shape."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from delta.invoicing.schemas import (
    InvoiceCreateRequest,
    InvoiceDecisionRequest,
    PaymentRecordRequest,
)

_TENANT = str(uuid.uuid4())
_VENDOR = str(uuid.uuid4())
_PO = str(uuid.uuid4())
_TASK = str(uuid.uuid4())


def _valid_invoice_kwargs() -> dict:
    return dict(
        tenant_id=_TENANT,
        vendor_id=_VENDOR,
        po_id=_PO,
        invoice_number="INV-0001",
        description="Q1 services",
        amount_minor_units=50_000,
        currency="USD",
        submitted_by="ap@example.com",
    )


def test_invoice_create_request_accepts_valid_payload() -> None:
    req = InvoiceCreateRequest(**_valid_invoice_kwargs())
    assert req.amount_minor_units == 50_000
    assert req.milestone_task_id is None


def test_invoice_create_request_accepts_milestone_task_id() -> None:
    req = InvoiceCreateRequest(**_valid_invoice_kwargs(), milestone_task_id=_TASK)
    assert req.milestone_task_id == _TASK


def test_invoice_create_request_rejects_float_amount() -> None:
    kwargs = _valid_invoice_kwargs()
    kwargs["amount_minor_units"] = 50_000.0
    with pytest.raises(ValidationError):
        InvoiceCreateRequest(**kwargs)


def test_invoice_create_request_rejects_bool_amount() -> None:
    kwargs = _valid_invoice_kwargs()
    kwargs["amount_minor_units"] = True
    with pytest.raises(ValidationError):
        InvoiceCreateRequest(**kwargs)


def test_invoice_create_request_rejects_negative_amount() -> None:
    kwargs = _valid_invoice_kwargs()
    kwargs["amount_minor_units"] = -1
    with pytest.raises(ValidationError):
        InvoiceCreateRequest(**kwargs)


def test_invoice_create_request_rejects_amount_over_max() -> None:
    kwargs = _valid_invoice_kwargs()
    kwargs["amount_minor_units"] = 100_000_000_001
    with pytest.raises(ValidationError):
        InvoiceCreateRequest(**kwargs)


def test_invoice_create_request_rejects_control_chars_in_invoice_number() -> None:
    kwargs = _valid_invoice_kwargs()
    kwargs["invoice_number"] = "INV-0001\n\rX-Injected: true"
    with pytest.raises(ValidationError):
        InvoiceCreateRequest(**kwargs)


def test_invoice_create_request_rejects_control_chars_in_description() -> None:
    kwargs = _valid_invoice_kwargs()
    kwargs["description"] = "line1\nline2"
    with pytest.raises(ValidationError):
        InvoiceCreateRequest(**kwargs)


def test_invoice_create_request_rejects_control_chars_in_submitted_by() -> None:
    kwargs = _valid_invoice_kwargs()
    kwargs["submitted_by"] = "ap@example.com\x00"
    with pytest.raises(ValidationError):
        InvoiceCreateRequest(**kwargs)


def test_invoice_create_request_rejects_unknown_field() -> None:
    kwargs = _valid_invoice_kwargs()
    kwargs["unexpected"] = "nope"
    with pytest.raises(ValidationError):
        InvoiceCreateRequest(**kwargs)


def test_invoice_create_request_rejects_empty_invoice_number() -> None:
    kwargs = _valid_invoice_kwargs()
    kwargs["invoice_number"] = ""
    with pytest.raises(ValidationError):
        InvoiceCreateRequest(**kwargs)


def test_invoice_decision_request_accepts_valid_payload() -> None:
    req = InvoiceDecisionRequest(tenant_id=_TENANT, action="approve", actor="ap@example.com")
    assert req.action == "approve"
    assert req.note is None


def test_invoice_decision_request_rejects_unknown_action() -> None:
    with pytest.raises(ValidationError):
        InvoiceDecisionRequest(tenant_id=_TENANT, action="cancel", actor="ap@example.com")


def test_invoice_decision_request_rejects_control_chars_in_note() -> None:
    with pytest.raises(ValidationError):
        InvoiceDecisionRequest(
            tenant_id=_TENANT, action="dispute", actor="ap@example.com", note="bad\x1b[31m"
        )


def _valid_payment_kwargs() -> dict:
    return dict(
        tenant_id=_TENANT,
        amount_minor_units=10_000,
        currency="USD",
        paid_at=datetime.now(timezone.utc),
        recorded_by="treasury@example.com",
    )


def test_payment_record_request_accepts_valid_payload() -> None:
    req = PaymentRecordRequest(**_valid_payment_kwargs())
    assert req.amount_minor_units == 10_000


def test_payment_record_request_rejects_zero_amount() -> None:
    kwargs = _valid_payment_kwargs()
    kwargs["amount_minor_units"] = 0
    with pytest.raises(ValidationError):
        PaymentRecordRequest(**kwargs)


def test_payment_record_request_rejects_negative_amount() -> None:
    kwargs = _valid_payment_kwargs()
    kwargs["amount_minor_units"] = -5
    with pytest.raises(ValidationError):
        PaymentRecordRequest(**kwargs)


def test_payment_record_request_rejects_naive_datetime() -> None:
    kwargs = _valid_payment_kwargs()
    kwargs["paid_at"] = datetime(2026, 7, 9, 12, 0, 0)  # no tzinfo
    with pytest.raises(ValidationError):
        PaymentRecordRequest(**kwargs)


def test_payment_record_request_rejects_float_amount() -> None:
    kwargs = _valid_payment_kwargs()
    kwargs["amount_minor_units"] = 10_000.5
    with pytest.raises(ValidationError):
        PaymentRecordRequest(**kwargs)
