"""ERP API request/response DTOs (D-014, ADR-0014).

A deliberately bounded vertical slice: a vendor directory, a physical/software asset
register, and a vendor/purchase-order procurement workflow — not the roadmap's literal
"full ERP" (no payroll, no HR, no external real-time sync; see ADR-0014 §3).

Mirrors D-007's `allocation_admin.schemas` (the PO propose/decide shape) and D-013's
`crm.schemas` (bounded free text, control-character rejection, `require_aware_utc`)
conventions throughout.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..identifiers import AssetId, PurchaseOrderId, TeamId, TenantId, VendorId
from ..money import DEFAULT_CURRENCY, Currency, require_aware_utc

AssetCategory = Literal["equipment", "software_license", "furniture", "vehicle", "other"]
AssetStatus = Literal["active", "retired", "disposed"]
_ASSET_STATUS_ORDER: tuple[AssetStatus, ...] = ("active", "retired", "disposed")

VendorStatus = Literal["active", "inactive"]

PurchaseOrderStatus = Literal["requested", "approved", "rejected"]
PurchaseOrderAction = Literal["approve", "reject"]

# Bounded free-text fields (mirrors D-007/D-013's storage-bloat + log-injection
# discipline).
_NAME_MAX_LENGTH = 256
_ACTOR_MAX_LENGTH = 128
_DESCRIPTION_MAX_LENGTH = 512
_NOTE_MAX_LENGTH = 1024
_EMAIL_MAX_LENGTH = 320
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

# A purchase order / asset acquisition cost is capped at the same order of magnitude as
# a Delta budget cap (delta.money.MAX_BUDGET_COST_CENTS) — a procurement commitment, not
# a ledger entry, so it does not reuse that exact constant, but an unbounded caller
# input should still be rejected (mirrors D-013's MAX_DEAL_VALUE_MINOR_UNITS).
MAX_PO_AMOUNT_MINOR_UNITS = 100_000_000_000  # 1e11 minor units
MAX_ASSET_COST_MINOR_UNITS = 100_000_000_000  # 1e11 minor units

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


def _validate_email(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    value = _reject_control_chars(value, field_name)
    if not _EMAIL_PATTERN.match(value):
        raise ValueError(f"{field_name} does not look like an email address")
    return value


class VendorCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    contact_email: str | None = Field(default=None, max_length=_EMAIL_MAX_LENGTH)

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")

    @field_validator("contact_email")
    @classmethod
    def _contact_email_shape(cls, value: str | None) -> str | None:
        return _validate_email(value, "contact_email")


class VendorView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor_id: VendorId
    tenant_id: TenantId
    name: str
    contact_email: str | None
    status: VendorStatus
    created_at: datetime
    updated_at: datetime


class AssetCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    category: AssetCategory
    acquisition_cost_minor_units: int | None = Field(
        default=None, ge=0, le=MAX_ASSET_COST_MINOR_UNITS
    )
    currency: Currency | None = DEFAULT_CURRENCY
    acquired_at: datetime | None = None
    assigned_team_id: TeamId | None = None

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")

    @field_validator("acquired_at")
    @classmethod
    def _acquired_at_aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value, "acquired_at")


class AssetStatusTransitionRequest(BaseModel):
    """Move an asset forward one step: active -> retired -> disposed. Rejected if the
    target is not the immediate next status, or the asset is already 'disposed'
    (ADR-0014 Fork 2 — mirrors D-013's deal-stage terminality guard)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    status: AssetStatus
    actor: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("actor")
    @classmethod
    def _actor_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "actor")


class AssetView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: AssetId
    tenant_id: TenantId
    name: str
    category: AssetCategory
    status: AssetStatus
    acquisition_cost_minor_units: int | None
    currency: Currency | None
    acquired_at: datetime | None
    assigned_team_id: TeamId | None
    retired_at: datetime | None
    created_at: datetime
    updated_at: datetime


class PurchaseOrderCreateRequest(BaseModel):
    """Propose a new purchase order (status starts 'requested' — never auto-approved,
    mirrors D-007's `AllocationCreateRequest`)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    vendor_id: VendorId
    asset_id: AssetId | None = None
    description: str = Field(min_length=1, max_length=_DESCRIPTION_MAX_LENGTH)
    amount_minor_units: int = Field(ge=0, le=MAX_PO_AMOUNT_MINOR_UNITS)
    currency: Currency = DEFAULT_CURRENCY
    requested_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("description")
    @classmethod
    def _description_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "description")

    @field_validator("requested_by")
    @classmethod
    def _requested_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "requested_by")


class PurchaseOrderDecisionRequest(BaseModel):
    """Approve or reject a 'requested' purchase order. Idempotent per PO — mirrors
    D-007's `ApprovalDecisionRequest` exactly."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    action: PurchaseOrderAction
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


class PurchaseOrderView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    po_id: PurchaseOrderId
    tenant_id: TenantId
    vendor_id: VendorId
    asset_id: AssetId | None
    description: str
    amount_minor_units: int
    currency: Currency
    status: PurchaseOrderStatus
    requested_by: str
    requested_at: datetime
    decided_by: str | None
    decided_at: datetime | None
