"""Bank-statement import API DTOs (D-025, ADR-0025).

Privacy-first at the schema layer: only whitelisted fields exist (``extra="forbid"``
everywhere — nothing a future aggregator sends but we don't need can even arrive),
and free-text fields REJECT long digit runs so a card/account number pasted into a
merchant descriptor is refused rather than stored (Fork 4).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..identifiers import (
    BankSourceId,
    ImportedLineId,
    PersonalAccountId,
    PersonalTransactionId,
    StatementImportId,
    TenantId,
)
from ..money import Currency, reject_non_integer, require_aware_utc
from ..personal_finance.schemas import MAX_AMOUNT_MINOR_UNITS, TransactionCategory

LineStatus = Literal["imported", "skipped_duplicate", "rejected"]
LineRejectedReason = Literal["currency_mismatch"]

_LABEL_MAX_LENGTH = 128
_ACTOR_MAX_LENGTH = 128
_DESCRIPTION_MAX_LENGTH = 512
_MERCHANT_MAX_LENGTH = 256
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# A run of 12+ digits (separators allowed between groups) in free text is almost
# certainly a card/account number (PAN/IBAN digits) leaking through a statement
# descriptor — refuse to store it (privacy-first, ADR-0025 Fork 4). 12 is below the
# shortest real PAN length (13), catching padded/truncated forms early, while
# ordinary references ("order 12345678") stay well under it.
_DIGIT_RUN_PATTERN = re.compile(r"(?:\d[ -]?){12,}")

# The bank-side transaction reference: an opaque caller token, hashed before storage
# (never persisted raw). Same log-injection-safe charset as the ecosystem request_id.
_EXTERNAL_REFERENCE_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"

# One import request is bounded — a statement export, not an unbounded firehose.
MAX_LINES_PER_IMPORT = 500

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


def _reject_digit_runs(value: str, field_name: str) -> str:
    if _DIGIT_RUN_PATTERN.search(value):
        raise ValueError(
            f"{field_name} contains a long digit run that looks like a card/account "
            "number — refusing to store it (privacy-first data minimization)"
        )
    return value


class SourceRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    account_id: PersonalAccountId
    institution_label: str = Field(min_length=1, max_length=_LABEL_MAX_LENGTH)
    created_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("institution_label")
    @classmethod
    def _label_clean(cls, value: str) -> str:
        return _reject_digit_runs(
            _reject_control_chars(value, "institution_label"), "institution_label"
        )

    @field_validator("created_by")
    @classmethod
    def _created_by_clean(cls, value: str) -> str:
        return _reject_control_chars(value, "created_by")


class SourceView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: BankSourceId
    tenant_id: TenantId
    account_id: PersonalAccountId
    institution_label: str
    created_by: str
    created_at: datetime


class StatementLine(BaseModel):
    """One normalized bank-statement line. This shape IS the future-aggregator
    integration contract (ADR-0025 Sec 1): a real provider connector normalizes its
    data into this and POSTs it through the same import endpoint."""

    model_config = ConfigDict(extra="forbid")

    external_reference: str = Field(pattern=_EXTERNAL_REFERENCE_PATTERN)
    amount_minor_units: int = Field(description="Negative = expense, positive = income.")
    currency: Currency
    occurred_at: datetime
    category: TransactionCategory = "other"
    merchant: str | None = Field(default=None, max_length=_MERCHANT_MAX_LENGTH)
    description: str = Field(default="", max_length=_DESCRIPTION_MAX_LENGTH)

    @field_validator("amount_minor_units")
    @classmethod
    def _amount_valid(cls, value: int) -> int:
        value = reject_non_integer(value, "amount_minor_units")
        if value == 0:
            raise ValueError("amount_minor_units must not be zero")
        if abs(value) > MAX_AMOUNT_MINOR_UNITS:
            raise ValueError(f"amount_minor_units must not exceed {MAX_AMOUNT_MINOR_UNITS}")
        return value

    @field_validator("merchant")
    @classmethod
    def _merchant_clean(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _reject_digit_runs(_reject_control_chars(value, "merchant"), "merchant")

    @field_validator("description")
    @classmethod
    def _description_clean(cls, value: str) -> str:
        return _reject_digit_runs(_reject_control_chars(value, "description"), "description")

    @model_validator(mode="after")
    def _occurred_at_aware(self) -> "StatementLine":
        require_aware_utc(self.occurred_at, "occurred_at")
        return self


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    imported_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)
    lines: list[StatementLine] = Field(min_length=1, max_length=MAX_LINES_PER_IMPORT)

    @field_validator("imported_by")
    @classmethod
    def _imported_by_clean(cls, value: str) -> str:
        return _reject_control_chars(value, "imported_by")


class LineOutcomeView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    line_id: ImportedLineId
    # The SHA-256 hex of the caller's external_reference — the raw reference is
    # never stored or echoed back from storage (the caller already has it).
    external_reference_hash: str
    status: LineStatus
    rejected_reason: LineRejectedReason | None
    txn_id: PersonalTransactionId | None


class ImportResultView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    import_id: StatementImportId
    tenant_id: TenantId
    source_id: BankSourceId
    imported_by: str
    imported_at: datetime
    records_supplied: int
    records_imported: int
    records_skipped_duplicate: int
    records_rejected: int
    lines: list[LineOutcomeView]


class ImportSummaryView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    import_id: StatementImportId
    tenant_id: TenantId
    source_id: BankSourceId
    imported_by: str
    imported_at: datetime
    records_supplied: int
    records_imported: int
    records_skipped_duplicate: int
    records_rejected: int
