"""Invoicing API request/response DTOs (D-018, ADR-0018).

A deliberately bounded vertical slice: a PO-backed invoice submission, an approve/
dispute decision, payment recording against an approved invoice, and a computed
per-vendor reconciliation report — an accounts-payable three-way match (purchase
order -> invoice -> payment), not real external ERP/bank-feed sync (see ADR-0018 §3).

Mirrors D-014's `erp.schemas` (the vendor/PO propose/decide shape, bounded free text,
control-character rejection, strict-integer money, `require_aware_utc`) conventions
throughout.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..identifiers import (
    InvoiceId,
    InvoicePaymentId,
    PurchaseOrderId,
    TaskId,
    TenantId,
    VendorId,
)
from ..money import DEFAULT_CURRENCY, Currency, reject_non_integer, require_aware_utc

InvoiceStatus = Literal["submitted", "approved", "disputed", "partially_paid", "paid"]
InvoiceDecisionAction = Literal["approve", "dispute"]

_INVOICE_NUMBER_MAX_LENGTH = 128
_DESCRIPTION_MAX_LENGTH = 512
_ACTOR_MAX_LENGTH = 128
_NOTE_MAX_LENGTH = 1024
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# An invoice/payment amount is capped at the same order of magnitude as a D-014 PO
# amount (mirrors `erp.schemas.MAX_PO_AMOUNT_MINOR_UNITS`) — a billing/settlement
# amount, not a ledger entry, so it does not reuse that exact constant, but an
# unbounded caller input is still rejected.
MAX_INVOICE_AMOUNT_MINOR_UNITS = 100_000_000_000  # 1e11 minor units

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


class InvoiceCreateRequest(BaseModel):
    """Submit a new invoice against an approved D-014 purchase order (status starts
    'submitted' — never auto-approved, mirrors D-014's `PurchaseOrderCreateRequest`).
    `milestone_task_id`, when present, is the roadmap's "project milestones/delivery
    metrics" tie-in — the service layer requires that D-015 task to already be
    'done' (ADR-0018 Fork 2)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    vendor_id: VendorId
    po_id: PurchaseOrderId
    milestone_task_id: TaskId | None = None
    invoice_number: str = Field(min_length=1, max_length=_INVOICE_NUMBER_MAX_LENGTH)
    description: str = Field(min_length=1, max_length=_DESCRIPTION_MAX_LENGTH)
    amount_minor_units: int = Field(gt=0, le=MAX_INVOICE_AMOUNT_MINOR_UNITS)
    currency: Currency = DEFAULT_CURRENCY
    submitted_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("amount_minor_units", mode="before")
    @classmethod
    def _amount_strict_integer(cls, value: object) -> object:
        return reject_non_integer(value, "amount_minor_units")

    @field_validator("invoice_number")
    @classmethod
    def _invoice_number_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "invoice_number")

    @field_validator("description")
    @classmethod
    def _description_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "description")

    @field_validator("submitted_by")
    @classmethod
    def _submitted_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "submitted_by")


class InvoiceDecisionRequest(BaseModel):
    """Approve or dispute a 'submitted' invoice. Idempotent per invoice — mirrors
    D-014's `PurchaseOrderDecisionRequest` exactly."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    action: InvoiceDecisionAction
    actor: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)
    note: str | None = Field(default=None, max_length=_NOTE_MAX_LENGTH)

    @field_validator("actor")
    @classmethod
    def _actor_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "actor")

    @field_validator("note")
    @classmethod
    def _note_no_control_chars(cls, value: str | None) -> str | None:
        return None if value is None else _reject_control_chars(value, "note")


class InvoiceView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    invoice_id: InvoiceId
    tenant_id: TenantId
    vendor_id: VendorId
    po_id: PurchaseOrderId
    milestone_task_id: TaskId | None
    invoice_number: str
    description: str
    amount_minor_units: int
    currency: Currency
    amount_paid_minor_units: int
    status: InvoiceStatus
    submitted_by: str
    submitted_at: datetime
    decided_by: str | None
    decided_at: datetime | None


class PaymentRecordRequest(BaseModel):
    """Record a vendor payment against an 'approved'/'partially_paid' invoice. Rejected
    if it would exceed the invoice's remaining unpaid balance (ADR-0018 Fork 3 — the
    conditional-UPDATE race-guard, mirroring D-007/D-013/D-014's decision-guard shape,
    extended to a computed-condition guard)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    amount_minor_units: int = Field(gt=0, le=MAX_INVOICE_AMOUNT_MINOR_UNITS)
    currency: Currency = DEFAULT_CURRENCY
    paid_at: datetime
    recorded_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)
    note: str | None = Field(default=None, max_length=_NOTE_MAX_LENGTH)

    @field_validator("amount_minor_units", mode="before")
    @classmethod
    def _amount_strict_integer(cls, value: object) -> object:
        return reject_non_integer(value, "amount_minor_units")

    @field_validator("paid_at")
    @classmethod
    def _paid_at_aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "paid_at")

    @field_validator("recorded_by")
    @classmethod
    def _recorded_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "recorded_by")

    @field_validator("note")
    @classmethod
    def _note_no_control_chars(cls, value: str | None) -> str | None:
        return None if value is None else _reject_control_chars(value, "note")


class InvoicePaymentView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payment_id: InvoicePaymentId
    tenant_id: TenantId
    invoice_id: InvoiceId
    amount_minor_units: int
    currency: Currency
    paid_at: datetime
    recorded_by: str
    note: str | None


class VendorReconciliationView(BaseModel):
    """One vendor's three-way-match snapshot: committed (approved PO totals),
    invoiced (non-disputed invoice totals), paid, and the derived outstanding
    balance. `over_invoiced` and `over_paid` are defense-in-depth reconciliation
    flags — the service-layer guards that create/pay invoices are already supposed
    to make both structurally impossible, so a `True` here means those guards were
    bypassed or a data-layer bug exists, exactly the complement-check philosophy
    `delta.reconciliation` already applies to ledger entries (ADR-0018 §4)."""

    model_config = ConfigDict(extra="forbid")

    vendor_id: VendorId
    currency: Currency
    committed_minor_units: int
    invoiced_minor_units: int
    paid_minor_units: int
    outstanding_minor_units: int
    disputed_invoice_count: int
    over_invoiced: bool
    over_paid: bool
