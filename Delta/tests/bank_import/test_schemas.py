"""D-025 pure schema-validation unit tests (no DB, no I/O)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from delta.bank_import.schemas import (
    MAX_LINES_PER_IMPORT,
    ImportRequest,
    SourceRegisterRequest,
    StatementLine,
)

_TENANT = "11111111-1111-4111-8111-111111111111"
_ACCOUNT = "22222222-2222-4222-8222-222222222222"


def _line(**overrides) -> StatementLine:
    payload = {
        "external_reference": "stmt-2026-07-001",
        "amount_minor_units": -1250,
        "currency": "USD",
        "occurred_at": datetime.now(timezone.utc),
    }
    payload.update(overrides)
    return StatementLine(**payload)


def test_valid_line_accepted() -> None:
    line = _line(merchant="Corner Cafe", description="coffee")
    assert line.category == "other"  # default


def test_card_number_like_text_rejected() -> None:
    with pytest.raises(ValidationError):
        _line(merchant="VISA 4111 1111 1111 1111")
    with pytest.raises(ValidationError):
        _line(description="ref 4111111111111111 thanks")
    with pytest.raises(ValidationError):
        SourceRegisterRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            institution_label="Acct 1234-5678-9012-3456",
            created_by="Jane",
        )


def test_short_digit_runs_allowed() -> None:
    line = _line(merchant="Store #12345", description="order 12345678")
    assert line.merchant == "Store #12345"


def test_control_characters_rejected() -> None:
    with pytest.raises(ValidationError):
        _line(merchant="Cafe\x00")
    with pytest.raises(ValidationError):
        _line(description="line1\nline2")


def test_external_reference_charset_constrained() -> None:
    with pytest.raises(ValidationError):
        _line(external_reference="ref with spaces")
    with pytest.raises(ValidationError):
        _line(external_reference="")


def test_amount_zero_rejected() -> None:
    with pytest.raises(ValidationError):
        _line(amount_minor_units=0)


def test_amount_rejects_float() -> None:
    with pytest.raises(ValidationError):
        _line(amount_minor_units=-12.50)


def test_naive_occurred_at_rejected() -> None:
    with pytest.raises(ValidationError):
        _line(occurred_at=datetime(2026, 7, 1, 12, 0, 0))


def test_income_and_transfer_categories_allowed() -> None:
    assert _line(category="income", amount_minor_units=250_000).category == "income"
    assert _line(category="transfer").category == "transfer"


def test_import_request_empty_lines_rejected() -> None:
    with pytest.raises(ValidationError):
        ImportRequest(tenant_id=_TENANT, imported_by="Jane", lines=[])


def test_import_over_max_lines_rejected() -> None:
    lines = [
        _line(external_reference=f"ref-{i}").model_dump() for i in range(MAX_LINES_PER_IMPORT + 1)
    ]
    with pytest.raises(ValidationError):
        ImportRequest(tenant_id=_TENANT, imported_by="Jane", lines=lines)


def test_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        _line(unexpected="nope")
    with pytest.raises(ValidationError):
        SourceRegisterRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            institution_label="Chase",
            created_by="Jane",
            raw_payload={"x": 1},
        )
