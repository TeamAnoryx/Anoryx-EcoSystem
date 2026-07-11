"""Personal-finance API request/response DTOs (D-021, ADR-0021).

A B2C consumer IS one `tenant_id` (Fork 1) — every request/view here is
tenant-scoped exactly like every B2B admin surface, with no separate consumer-
identity field. Mirrors D-013/D-014/D-018/D-019's bounded free-text + control-
character rejection + `require_aware_utc` conventions throughout.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..identifiers import PersonalAccountId, PersonalBudgetId, PersonalTransactionId, TenantId
from ..money import Currency, reject_non_integer, require_aware_utc

AccountType = Literal["checking", "savings", "credit_card", "cash", "investment"]

# 'income' and 'transfer' are transaction categories but not budgetable spending
# categories (a "budget" caps discretionary/fixed spend, not money coming in or
# moving between one's own accounts).
TransactionCategory = Literal[
    "groceries",
    "rent",
    "utilities",
    "dining",
    "transport",
    "entertainment",
    "subscriptions",
    "healthcare",
    "income",
    "transfer",
    "other",
]
BudgetCategory = Literal[
    "groceries",
    "rent",
    "utilities",
    "dining",
    "transport",
    "entertainment",
    "subscriptions",
    "healthcare",
    "other",
]
BudgetPeriod = Literal["monthly"]
TransactionSource = Literal["manual"]

_NAME_MAX_LENGTH = 256
_DESCRIPTION_MAX_LENGTH = 512
_MERCHANT_MAX_LENGTH = 256
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# Same order of magnitude as every other Delta monetary field's overflow guard
# (mirrors erp.schemas.MAX_PO_AMOUNT_MINOR_UNITS) — a personal transaction/budget cap
# is capped well above any plausible real value, purely as an overflow guard.
MAX_AMOUNT_MINOR_UNITS = 100_000_000_000  # 1e11 minor units

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


class AccountCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    type: AccountType
    currency: Currency
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")


class AccountView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_id: PersonalAccountId
    tenant_id: TenantId
    type: AccountType
    currency: Currency
    name: str
    created_at: datetime


class TransactionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    account_id: PersonalAccountId
    category: TransactionCategory
    amount_minor_units: int = Field(description="Negative = expense, positive = income.")
    currency: Currency
    description: str = Field(default="", max_length=_DESCRIPTION_MAX_LENGTH)
    merchant: str | None = Field(default=None, max_length=_MERCHANT_MAX_LENGTH)
    occurred_at: datetime

    @field_validator("amount_minor_units")
    @classmethod
    def _amount_valid(cls, value: int) -> int:
        value = reject_non_integer(value, "amount_minor_units")
        if value == 0:
            raise ValueError("amount_minor_units must not be zero")
        if abs(value) > MAX_AMOUNT_MINOR_UNITS:
            raise ValueError(f"amount_minor_units must not exceed {MAX_AMOUNT_MINOR_UNITS}")
        return value

    @field_validator("description")
    @classmethod
    def _description_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "description")

    @field_validator("merchant")
    @classmethod
    def _merchant_no_control_chars(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _reject_control_chars(value, "merchant")

    @model_validator(mode="after")
    def _validate_occurred_at(self) -> "TransactionCreateRequest":
        require_aware_utc(self.occurred_at, "occurred_at")
        return self


class TransactionView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    txn_id: PersonalTransactionId
    tenant_id: TenantId
    account_id: PersonalAccountId
    category: TransactionCategory
    amount_minor_units: int
    currency: Currency
    description: str
    merchant: str | None
    occurred_at: datetime
    created_at: datetime
    source: TransactionSource


class BudgetCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    category: BudgetCategory
    cap_minor_units: int
    currency: Currency
    period: BudgetPeriod = "monthly"

    @field_validator("cap_minor_units")
    @classmethod
    def _cap_valid(cls, value: int) -> int:
        value = reject_non_integer(value, "cap_minor_units")
        if value <= 0:
            raise ValueError("cap_minor_units must be positive")
        if value > MAX_AMOUNT_MINOR_UNITS:
            raise ValueError(f"cap_minor_units must not exceed {MAX_AMOUNT_MINOR_UNITS}")
        return value


class BudgetView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    budget_id: PersonalBudgetId
    tenant_id: TenantId
    category: BudgetCategory
    cap_minor_units: int
    currency: Currency
    period: BudgetPeriod
    created_at: datetime


class FinancialHealthQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _validate_window(self) -> "FinancialHealthQuery":
        require_aware_utc(self.start, "start")
        require_aware_utc(self.end, "end")
        if self.end <= self.start:
            raise ValueError("end must be after start")
        return self


class BudgetStatusView(BaseModel):
    """One category's spend-vs-cap for the queried window (ADR-0021 §2 Fork 3: a
    deterministic comparison, not a forecast/projection — that's D-011's job for the
    B2B AI-cost domain; this is a same-period actual-vs-cap read)."""

    model_config = ConfigDict(extra="forbid")

    category: BudgetCategory
    cap_minor_units: int
    spent_minor_units: int
    currency: Currency
    over_cap: bool


class FinancialHealthView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    currency: Currency
    total_income_minor_units: int
    total_expense_minor_units: int
    # None iff total_income_minor_units is 0 (never a divide-by-zero placeholder —
    # mirrors D-008's SpendSummaryView.cost_per_request_cents convention).
    savings_rate: float | None
    budgets: list[BudgetStatusView]
    # A DETERMINISTIC heuristic score (0-100), NOT machine learning / AI (mirrors
    # D-011's "predictive" forecasting and D-015's "AI-driven" bottleneck detection —
    # both plain arithmetic, not a trained model). See service.py's docstring for the
    # exact, disclosed formula.
    health_score: int
