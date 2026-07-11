"""D-024 pure schema-validation unit tests (no DB, no I/O)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from delta.micro_transactions.schemas import (
    MAX_MICRO_TRANSACTION_MINOR_UNITS,
    ExecutionRequest,
)

_TENANT = "11111111-1111-4111-8111-111111111111"
_ACCOUNT = "22222222-2222-4222-8222-222222222222"


def _request(**overrides) -> ExecutionRequest:
    payload = {
        "tenant_id": _TENANT,
        "account_id": _ACCOUNT,
        "idempotency_key": "key-001",
        "amount_minor_units": 500,
        "currency": "USD",
        "category": "dining",
        "requested_by": "Jane",
    }
    payload.update(overrides)
    return ExecutionRequest(**payload)


def test_valid_request_accepted() -> None:
    req = _request()
    assert req.amount_minor_units == 500


def test_amount_above_micro_cap_rejected() -> None:
    with pytest.raises(ValidationError):
        _request(amount_minor_units=MAX_MICRO_TRANSACTION_MINOR_UNITS + 1)


def test_amount_at_micro_cap_accepted() -> None:
    req = _request(amount_minor_units=MAX_MICRO_TRANSACTION_MINOR_UNITS)
    assert req.amount_minor_units == MAX_MICRO_TRANSACTION_MINOR_UNITS


def test_amount_zero_rejected() -> None:
    with pytest.raises(ValidationError):
        _request(amount_minor_units=0)


def test_amount_negative_rejected() -> None:
    with pytest.raises(ValidationError):
        _request(amount_minor_units=-500)


def test_amount_rejects_float() -> None:
    with pytest.raises(ValidationError):
        _request(amount_minor_units=500.0)


def test_amount_rejects_bool() -> None:
    with pytest.raises(ValidationError):
        _request(amount_minor_units=True)


def test_income_is_not_an_execution_category() -> None:
    with pytest.raises(ValidationError):
        _request(category="income")


def test_idempotency_key_charset_constrained() -> None:
    with pytest.raises(ValidationError):
        _request(idempotency_key="key with spaces")
    with pytest.raises(ValidationError):
        _request(idempotency_key="key\nnewline")
    with pytest.raises(ValidationError):
        _request(idempotency_key="")


def test_control_characters_rejected() -> None:
    with pytest.raises(ValidationError):
        _request(merchant="Cafe\x00")
    with pytest.raises(ValidationError):
        _request(description="line1\nline2")
    with pytest.raises(ValidationError):
        _request(requested_by="Jane\x1b[31m")


def test_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        _request(unexpected="nope")
