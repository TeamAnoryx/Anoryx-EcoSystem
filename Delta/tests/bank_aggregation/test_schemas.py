"""D-025 pure schema-validation unit tests (no DB, no I/O)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from delta.bank_aggregation.schemas import (
    MAX_AMOUNT_MINOR_UNITS,
    LinkCreateRequest,
    LinkRevokeRequest,
    SyncLineItemInput,
    SyncRunCreateRequest,
)

_TENANT = "11111111-1111-4111-8111-111111111111"
_ACCOUNT = "22222222-2222-4222-8222-222222222222"


def _link_request(**overrides) -> LinkCreateRequest:
    payload = {
        "tenant_id": _TENANT,
        "account_id": _ACCOUNT,
        "institution_name": "First Bank",
        "masked_account_last4": "1234",
        "consent_confirmed": True,
        "requested_by": "Jane",
    }
    payload.update(overrides)
    return LinkCreateRequest(**payload)


def _line_item(**overrides) -> dict:
    payload = {
        "external_reference": "bank-txn-001",
        "category": "groceries",
        "amount_minor_units": -500,
        "currency": "USD",
        "occurred_at": "2026-07-01T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def test_valid_link_request_accepted() -> None:
    req = _link_request()
    assert req.masked_account_last4 == "1234"


def test_link_requires_consent_true() -> None:
    with pytest.raises(ValidationError):
        _link_request(consent_confirmed=False)


def test_masked_last4_must_be_exactly_four_digits() -> None:
    with pytest.raises(ValidationError):
        _link_request(masked_account_last4="123")
    with pytest.raises(ValidationError):
        _link_request(masked_account_last4="12345")
    with pytest.raises(ValidationError):
        _link_request(masked_account_last4="abcd")


def test_masked_last4_cannot_carry_a_full_account_number() -> None:
    with pytest.raises(ValidationError):
        _link_request(masked_account_last4="123456789012")


def test_link_institution_name_rejects_control_chars() -> None:
    with pytest.raises(ValidationError):
        _link_request(institution_name="Evil\nBank")


def test_link_requested_by_rejects_control_chars() -> None:
    with pytest.raises(ValidationError):
        _link_request(requested_by="Jane\x00")


def test_link_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        _link_request(unexpected="nope")


def test_revoke_request_requires_actor() -> None:
    with pytest.raises(ValidationError):
        LinkRevokeRequest(tenant_id=_TENANT, requested_by="")


def test_revoke_request_rejects_control_chars() -> None:
    with pytest.raises(ValidationError):
        LinkRevokeRequest(tenant_id=_TENANT, requested_by="Jane\x1b[31m")


def test_line_item_valid_accepted() -> None:
    item = SyncLineItemInput(**_line_item())
    assert item.amount_minor_units == -500


def test_line_item_rejects_zero_amount() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(**_line_item(amount_minor_units=0))


def test_line_item_rejects_overflow_amount() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(**_line_item(amount_minor_units=MAX_AMOUNT_MINOR_UNITS + 1))


def test_line_item_rejects_float_amount() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(**_line_item(amount_minor_units=500.0))


def test_line_item_rejects_bool_amount() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(**_line_item(amount_minor_units=True))


def test_line_item_income_category_allowed() -> None:
    item = SyncLineItemInput(**_line_item(category="income", amount_minor_units=250000))
    assert item.category == "income"


def test_line_item_external_reference_charset_constrained() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(**_line_item(external_reference="ref with spaces"))
    with pytest.raises(ValidationError):
        SyncLineItemInput(**_line_item(external_reference=""))
    with pytest.raises(ValidationError):
        SyncLineItemInput(**_line_item(external_reference="ref\nnewline"))


def test_line_item_rejects_naive_occurred_at() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(**_line_item(occurred_at="2026-07-01T00:00:00"))


def test_line_item_control_chars_rejected() -> None:
    with pytest.raises(ValidationError):
        SyncLineItemInput(**_line_item(merchant="Cafe\x00"))
    with pytest.raises(ValidationError):
        SyncLineItemInput(**_line_item(description="line1\nline2"))


def test_sync_run_request_requires_at_least_one_line_item() -> None:
    with pytest.raises(ValidationError):
        SyncRunCreateRequest(tenant_id=_TENANT, triggered_by="cron", line_items=[])


def test_sync_run_request_caps_batch_size() -> None:
    items = [_line_item(external_reference=f"ref-{i}") for i in range(501)]
    with pytest.raises(ValidationError):
        SyncRunCreateRequest(tenant_id=_TENANT, triggered_by="cron", line_items=items)


def test_sync_run_request_rejects_control_chars_in_note() -> None:
    with pytest.raises(ValidationError):
        SyncRunCreateRequest(
            tenant_id=_TENANT,
            triggered_by="cron",
            line_items=[_line_item()],
            note="bad\nnote",
        )


def test_sync_run_request_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        SyncRunCreateRequest(
            tenant_id=_TENANT, triggered_by="cron", line_items=[_line_item()], unexpected="nope"
        )
