"""Privacy-first multi-bank aggregation API DTOs (D-025, ADR-0025).

A generic ingestion FRAMEWORK — mirrors D-019's own "generic ingestion endpoint, not
vendor connectors" precedent (ADR-0021 Sec 3 names this exact shape as D-025's job)
over D-021's personal ledger. NOT a live Plaid/bank-OAuth integration: nothing here
ever stores a bank credential/access token, and only a MASKED last-4 account
reference may ever be recorded — enforced by a DB CHECK (migration 0018), not just
this schema layer. Mirrors D-021/D-024's bounded free-text + control-character
rejection + strict-integer money + ``require_aware_utc`` conventions throughout.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..identifiers import (
    AggregationSyncRunId,
    LinkedInstitutionId,
    PersonalAccountId,
    TenantId,
)
from ..money import Currency, reject_non_integer, require_aware_utc
from ..personal_finance.schemas import TransactionCategory

LinkStatus = Literal["linked", "revoked"]

_INSTITUTION_NAME_MAX_LENGTH = 256
_ACTOR_MAX_LENGTH = 128
_DESCRIPTION_MAX_LENGTH = 512
_MERCHANT_MAX_LENGTH = 256
_NOTE_MAX_LENGTH = 1024
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# Structural privacy control at the wire layer too (the DB CHECK, migration 0018, is
# the real backstop): exactly four digits, never anything that could be a full
# account/routing number.
_MASKED_LAST4_PATTERN = r"^[0-9]{4}$"

# Mirrors D-024's idempotency-key charset (log-injection-safe, request-id shaped) —
# reused here as the shape for a bank's own transaction-reference identifier.
_EXTERNAL_REFERENCE_PATTERN = r"^[A-Za-z0-9._-]{1,128}$"

# Same order of magnitude as every other Delta monetary field's overflow guard.
MAX_AMOUNT_MINOR_UNITS = 100_000_000_000  # 1e11 minor units

# A single sync call is bounded — mirrors D-019's SyncRunCreateRequest.line_items cap.
MAX_SYNC_BATCH_SIZE = 500

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


class LinkCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    account_id: PersonalAccountId
    institution_name: str = Field(min_length=1, max_length=_INSTITUTION_NAME_MAX_LENGTH)
    masked_account_last4: str = Field(pattern=_MASKED_LAST4_PATTERN)
    # An explicit, caller-affirmed consent gate — a link cannot be created "by
    # default"; the caller must affirmatively pass true. Privacy-first: consent is a
    # real, checked gate, not implied by the request simply existing.
    consent_confirmed: Literal[True]
    requested_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("institution_name")
    @classmethod
    def _institution_name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "institution_name")

    @field_validator("requested_by")
    @classmethod
    def _requested_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "requested_by")


class LinkRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    requested_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("requested_by")
    @classmethod
    def _requested_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "requested_by")


class LinkView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    link_id: LinkedInstitutionId
    tenant_id: TenantId
    account_id: PersonalAccountId
    institution_name: str
    masked_account_last4: str
    status: LinkStatus
    consent_granted_at: datetime
    consent_revoked_at: datetime | None
    created_at: datetime


class SyncLineItemInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    external_reference: str = Field(pattern=_EXTERNAL_REFERENCE_PATTERN)
    category: TransactionCategory
    # Signed, per D-021's own convention: negative = expense/debit, positive =
    # income/credit — exactly what a normalized bank feed would report.
    amount_minor_units: int
    currency: Currency
    description: str = Field(default="", max_length=_DESCRIPTION_MAX_LENGTH)
    merchant: str | None = Field(default=None, max_length=_MERCHANT_MAX_LENGTH)
    occurred_at: datetime

    @field_validator("amount_minor_units", mode="before")
    @classmethod
    def _amount_valid(cls, value: object) -> object:
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
        return None if value is None else _reject_control_chars(value, "merchant")

    @model_validator(mode="after")
    def _validate_occurred_at(self) -> "SyncLineItemInput":
        require_aware_utc(self.occurred_at, "occurred_at")
        return self


class SyncRunCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    triggered_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)
    line_items: list[SyncLineItemInput] = Field(min_length=1, max_length=MAX_SYNC_BATCH_SIZE)
    note: str | None = Field(default=None, max_length=_NOTE_MAX_LENGTH)

    @field_validator("triggered_by")
    @classmethod
    def _triggered_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "triggered_by")

    @field_validator("note")
    @classmethod
    def _note_no_control_chars(cls, value: str | None) -> str | None:
        return None if value is None else _reject_control_chars(value, "note")


class SyncRunView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sync_run_id: AggregationSyncRunId
    tenant_id: TenantId
    link_id: LinkedInstitutionId
    triggered_by: str
    started_at: datetime
    completed_at: datetime
    records_received: int
    records_written: int
    records_deduplicated: int
    records_rejected: int
    note: str | None
