"""Micro-transaction execution API DTOs (D-024, ADR-0024).

Mirrors D-021's ``personal_finance.schemas`` (bounded free text, control-character
rejection, strict-integer money) — the execution engine writes into that package's
ledger, so its vocabulary (categories, amount conventions) is reused, not re-invented.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..identifiers import (
    MicroTransactionExecutionId,
    PersonalAccountId,
    PersonalTransactionId,
    TenantId,
)
from ..money import Currency, reject_non_integer

# D-021's TransactionCategory minus 'income' — an executed micro-transaction is a
# payment (an expense), never an income event (migration 0016's DB CHECK mirrors this).
ExecutionCategory = Literal[
    "groceries",
    "rent",
    "utilities",
    "dining",
    "transport",
    "entertainment",
    "subscriptions",
    "healthcare",
    "transfer",
    "other",
]
ExecutionStatus = Literal["executed", "rejected"]
# The per-transaction "micro" cap is enforced at the request-validation layer
# (`amount_minor_units le=MAX_MICRO_TRANSACTION_MINOR_UNITS` -> 422, never reaching
# the engine), so it is deliberately NOT a recordable rejection reason here — only
# conditions that depend on DB state at execution time are.
RejectionReason = Literal[
    "daily_cap_exceeded",
    "currency_mismatch",
]

_ACTOR_MAX_LENGTH = 128
_DESCRIPTION_MAX_LENGTH = 512
_MERCHANT_MAX_LENGTH = 256
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# The definition of "micro": a single execution may not exceed this magnitude.
# A module constant, not a query parameter — the cap is a safety property of the
# engine, not a caller-tunable knob (mirrors D-012's ratio_threshold posture).
MAX_MICRO_TRANSACTION_MINOR_UNITS = 10_000  # $100.00

# Rolling 24h cumulative executed-spend ceiling per account.
DAILY_CAP_MINOR_UNITS = 50_000  # $500.00

# Idempotency keys are client-generated opaque tokens; the charset mirrors the
# ecosystem's request_id rule (log-injection-safe, no control characters possible).
_IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9._-]{1,128}$"

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


class ExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    account_id: PersonalAccountId
    idempotency_key: str = Field(pattern=_IDEMPOTENCY_KEY_PATTERN)
    # The magnitude to pay, always positive; the D-021 ledger row this produces
    # carries the negative (expense) sign per that package's signed-amount convention.
    amount_minor_units: int = Field(gt=0, le=MAX_MICRO_TRANSACTION_MINOR_UNITS)
    currency: Currency
    category: ExecutionCategory
    merchant: str | None = Field(default=None, max_length=_MERCHANT_MAX_LENGTH)
    description: str = Field(default="", max_length=_DESCRIPTION_MAX_LENGTH)
    requested_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("amount_minor_units", mode="before")
    @classmethod
    def _amount_strict_integer(cls, value: object) -> object:
        return reject_non_integer(value, "amount_minor_units")

    @field_validator("merchant")
    @classmethod
    def _merchant_no_control_chars(cls, value: str | None) -> str | None:
        return None if value is None else _reject_control_chars(value, "merchant")

    @field_validator("description")
    @classmethod
    def _description_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "description")

    @field_validator("requested_by")
    @classmethod
    def _requested_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "requested_by")


class ExecutionView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: MicroTransactionExecutionId
    tenant_id: TenantId
    account_id: PersonalAccountId
    idempotency_key: str
    amount_minor_units: int
    currency: Currency
    category: ExecutionCategory
    merchant: str | None
    description: str
    status: ExecutionStatus
    rejection_reason: RejectionReason | None
    # The D-021 personal_transactions ledger row this execution produced —
    # set iff status == 'executed'.
    txn_id: PersonalTransactionId | None
    requested_by: str
    executed_at: datetime
    # True iff this response is the stored result of a PRIOR request replayed via
    # the same idempotency key — nothing was re-executed.
    idempotent_replay: bool = False
