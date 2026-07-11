"""D-021 pure schema validation (no DB)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from delta.personal_finance.schemas import (
    AccountCreateRequest,
    BudgetCreateRequest,
    FinancialHealthQuery,
    TransactionCreateRequest,
)

_TENANT = str(uuid.uuid4())
_ACCOUNT = str(uuid.uuid4())
_START = datetime(2026, 7, 1, tzinfo=timezone.utc)
_END = _START + timedelta(days=30)


def test_account_create_request_accepts_valid_payload() -> None:
    req = AccountCreateRequest(tenant_id=_TENANT, type="checking", currency="USD", name="Main")
    assert req.name == "Main"


def test_account_create_request_rejects_control_chars_in_name() -> None:
    with pytest.raises(ValidationError):
        AccountCreateRequest(tenant_id=_TENANT, type="checking", currency="USD", name="Main\x00")


def test_account_create_request_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        AccountCreateRequest(
            tenant_id=_TENANT, type="checking", currency="USD", name="Main", unexpected="nope"
        )


def test_transaction_create_request_accepts_valid_expense() -> None:
    req = TransactionCreateRequest(
        tenant_id=_TENANT,
        account_id=_ACCOUNT,
        category="groceries",
        amount_minor_units=-4200,
        currency="USD",
        occurred_at=_START,
    )
    assert req.amount_minor_units == -4200


def test_transaction_create_request_rejects_zero_amount() -> None:
    with pytest.raises(ValidationError):
        TransactionCreateRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            category="groceries",
            amount_minor_units=0,
            currency="USD",
            occurred_at=_START,
        )


def test_transaction_create_request_rejects_overflow_amount() -> None:
    with pytest.raises(ValidationError):
        TransactionCreateRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            category="groceries",
            amount_minor_units=-(10**12),
            currency="USD",
            occurred_at=_START,
        )


def test_transaction_create_request_rejects_naive_occurred_at() -> None:
    with pytest.raises(ValidationError):
        TransactionCreateRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            category="groceries",
            amount_minor_units=-100,
            currency="USD",
            occurred_at=datetime(2026, 7, 1),
        )


def test_transaction_create_request_rejects_control_chars_in_merchant() -> None:
    with pytest.raises(ValidationError):
        TransactionCreateRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            category="groceries",
            amount_minor_units=-100,
            currency="USD",
            occurred_at=_START,
            merchant="Acme\x1b[31m",
        )


def test_budget_create_request_accepts_valid_payload() -> None:
    req = BudgetCreateRequest(
        tenant_id=_TENANT, category="groceries", cap_minor_units=50_000, currency="USD"
    )
    assert req.period == "monthly"


def test_budget_create_request_rejects_zero_cap() -> None:
    with pytest.raises(ValidationError):
        BudgetCreateRequest(
            tenant_id=_TENANT, category="groceries", cap_minor_units=0, currency="USD"
        )


def test_budget_create_request_rejects_income_category() -> None:
    # 'income' is a valid transaction category but not a budgetable spending category.
    with pytest.raises(ValidationError):
        BudgetCreateRequest(
            tenant_id=_TENANT, category="income", cap_minor_units=50_000, currency="USD"
        )


def test_financial_health_query_accepts_valid_window() -> None:
    query = FinancialHealthQuery(tenant_id=_TENANT, start=_START, end=_END)
    assert query.end > query.start


def test_financial_health_query_rejects_end_before_start() -> None:
    with pytest.raises(ValidationError):
        FinancialHealthQuery(tenant_id=_TENANT, start=_END, end=_START)


def test_financial_health_query_rejects_naive_start() -> None:
    with pytest.raises(ValidationError):
        FinancialHealthQuery(tenant_id=_TENANT, start=datetime(2026, 7, 1), end=_END)
