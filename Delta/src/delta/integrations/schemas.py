"""Corporate ERP/procurement/cloud-cost sync API request/response DTOs (D-019,
ADR-0019).

A deliberately bounded vertical slice: a registered external-system directory + a
sync-ingestion endpoint that reconciles caller-supplied line items against D-014
purchase orders / D-018 invoices by exact ID + amount/currency match — not seven live
OAuth/API integrations with NetSuite/SAP/Coupa/Ariba/AWS/GCP/Azure (see ADR-0019 §3).

Mirrors D-018's `invoicing.schemas` (bounded free text, control-character rejection,
strict-integer money) conventions throughout.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..identifiers import (
    ExternalSystemId,
    InvoiceId,
    PurchaseOrderId,
    SyncLineItemId,
    SyncRunId,
    TenantId,
)
from ..money import Currency, reject_non_integer

SystemType = Literal["corporate_erp", "procurement", "cloud_cost"]
SystemStatus = Literal["active", "disabled"]
MatchedStatus = Literal["matched", "amount_mismatch", "not_found", "unreconciled"]
MatchedEntityType = Literal["purchase_order", "invoice"]

_NAME_MAX_LENGTH = 256
_VENDOR_LABEL_MAX_LENGTH = 128
_ACTOR_MAX_LENGTH = 128
_EXTERNAL_REFERENCE_MAX_LENGTH = 256
_NOTE_MAX_LENGTH = 1024
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# A sync line item's amount is capped at the same order of magnitude as a D-018
# invoice amount — an external system's own reported figure, not a ledger entry, but
# an unbounded caller input is still rejected.
MAX_LINE_ITEM_AMOUNT_MINOR_UNITS = 100_000_000_000  # 1e11 minor units

# One sync run's line-item payload is bounded — an unattended ingestion endpoint
# should not accept an unbounded request body (mirrors every other Delta list-response
# cap, applied here to the request side instead).
MAX_LINE_ITEMS_PER_SYNC = 500

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


class ExternalSystemCreateRequest(BaseModel):
    """Register a connector target. `vendor_label` is an operator-typed free string
    ("NetSuite", "AWS", ...) — NOT a live API credential or endpoint; see ADR-0019 §3."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    system_type: SystemType
    vendor_label: str = Field(min_length=1, max_length=_VENDOR_LABEL_MAX_LENGTH)

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")

    @field_validator("vendor_label")
    @classmethod
    def _vendor_label_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "vendor_label")


class ExternalSystemView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    system_id: ExternalSystemId
    tenant_id: TenantId
    name: str
    system_type: SystemType
    vendor_label: str
    status: SystemStatus
    created_at: datetime
    updated_at: datetime


class SyncLineItemInput(BaseModel):
    """One externally-reported line item to reconcile. At most one of `po_id`/
    `invoice_id` may be supplied — omitting both is the honest default for a
    line item with no Delta-side counterpart (e.g. a cloud-cost line), yielding
    `matched_status = 'unreconciled'` rather than a forced, meaningless match."""

    model_config = ConfigDict(extra="forbid")

    external_reference: str = Field(min_length=1, max_length=_EXTERNAL_REFERENCE_MAX_LENGTH)
    amount_minor_units: int = Field(ge=0, le=MAX_LINE_ITEM_AMOUNT_MINOR_UNITS)
    currency: Currency
    po_id: PurchaseOrderId | None = None
    invoice_id: InvoiceId | None = None

    @field_validator("amount_minor_units", mode="before")
    @classmethod
    def _amount_strict_integer(cls, value: object) -> object:
        return reject_non_integer(value, "amount_minor_units")

    @field_validator("external_reference")
    @classmethod
    def _external_reference_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "external_reference")

    @model_validator(mode="after")
    def _at_most_one_reference(self) -> "SyncLineItemInput":
        if self.po_id is not None and self.invoice_id is not None:
            raise ValueError("a sync line item may reference at most one of po_id/invoice_id")
        return self


class SyncRunCreateRequest(BaseModel):
    """Ingest a batch of externally-reported line items and reconcile each against
    Delta's own records. Synchronous — see ADR-0019 §3 (no live external I/O today)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    triggered_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)
    note: str | None = Field(default=None, max_length=_NOTE_MAX_LENGTH)
    line_items: list[SyncLineItemInput] = Field(min_length=1, max_length=MAX_LINE_ITEMS_PER_SYNC)

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

    sync_run_id: SyncRunId
    tenant_id: TenantId
    system_id: ExternalSystemId
    triggered_by: str
    started_at: datetime
    completed_at: datetime
    records_ingested: int
    records_matched: int
    records_mismatched: int
    records_not_found: int
    records_unreconciled: int
    note: str | None


class SyncLineItemView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    line_item_id: SyncLineItemId
    tenant_id: TenantId
    sync_run_id: SyncRunId
    external_reference: str
    amount_minor_units: int
    currency: Currency
    matched_status: MatchedStatus
    matched_entity_type: MatchedEntityType | None
    matched_entity_id: str | None


class SystemReconciliationView(BaseModel):
    """A per-system rollup across every sync run to date — counts and total amounts
    by `matched_status`, so an operator can see cumulative drift without paging
    through individual runs."""

    model_config = ConfigDict(extra="forbid")

    system_id: ExternalSystemId
    total_runs: int
    matched_count: int
    mismatched_count: int
    not_found_count: int
    unreconciled_count: int
    mismatched_amount_minor_units: int
