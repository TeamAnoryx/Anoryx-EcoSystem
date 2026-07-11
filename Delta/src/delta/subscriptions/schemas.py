"""Subscription registry + charge-ledger + anomaly-report API DTOs (D-022,
ADR-0021).

Mirrors D-014's ``erp.schemas`` (bounded free text, control-character rejection,
value/currency pairing) and D-012's ``chargeback.schemas`` (the anomaly report shape,
reused literal-for-literal where the underlying method is the same — see
ADR-0021 Fork 1).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..identifiers import SubscriptionChargeId, SubscriptionId, TenantId, VendorId
from ..money import DEFAULT_CURRENCY, Currency, reject_non_integer, require_aware_utc

SubscriptionCadence = Literal["weekly", "monthly", "quarterly", "annual"]
SubscriptionStatus = Literal["active", "cancelled"]

_NAME_MAX_LENGTH = 256
_ACTOR_MAX_LENGTH = 128
_NOTE_MAX_LENGTH = 1024
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# Same order of magnitude as D-014's PO/asset cost caps — a recurring commitment,
# not a ledger entry, but still rejects an unbounded caller input.
MAX_SUBSCRIPTION_AMOUNT_MINOR_UNITS = 100_000_000_000  # 1e11 minor units

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500

# How many of a subscription's most recent PRIOR charges to average as its trailing
# baseline (ADR-0021 Fork 2). Bounded the same shape as D-012's `baseline_periods`.
DEFAULT_BASELINE_WINDOW = 6
MAX_BASELINE_WINDOW = 24


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


class SubscriptionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    vendor_id: VendorId | None = None
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    expected_amount_minor_units: int | None = Field(
        default=None, ge=0, le=MAX_SUBSCRIPTION_AMOUNT_MINOR_UNITS
    )
    currency: Currency | None = DEFAULT_CURRENCY
    cadence: SubscriptionCadence
    created_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")

    @field_validator("created_by")
    @classmethod
    def _created_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "created_by")

    @field_validator("expected_amount_minor_units", mode="before")
    @classmethod
    def _amount_strict_integer(cls, value: object) -> object:
        # Reject a wire float like 100.0 rather than silently coercing it — the same
        # discipline every other Delta monetary field applies (mirrors D-014's
        # AssetCreateRequest._cost_strict_integer).
        return value if value is None else reject_non_integer(value, "expected_amount_minor_units")


class SubscriptionCancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    actor: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("actor")
    @classmethod
    def _actor_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "actor")


class SubscriptionView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subscription_id: SubscriptionId
    tenant_id: TenantId
    vendor_id: VendorId | None
    name: str
    expected_amount_minor_units: int | None
    currency: str | None
    cadence: SubscriptionCadence
    status: SubscriptionStatus
    created_by: str
    created_at: datetime
    updated_at: datetime
    cancelled_at: datetime | None


class ChargeRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    amount_minor_units: int = Field(ge=0, le=MAX_SUBSCRIPTION_AMOUNT_MINOR_UNITS)
    currency: Currency = DEFAULT_CURRENCY
    charged_at: datetime
    recorded_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)
    note: str | None = Field(default=None, max_length=_NOTE_MAX_LENGTH)

    @field_validator("recorded_by")
    @classmethod
    def _recorded_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "recorded_by")

    @field_validator("note")
    @classmethod
    def _note_no_control_chars(cls, value: str | None) -> str | None:
        return None if value is None else _reject_control_chars(value, "note")

    @field_validator("amount_minor_units", mode="before")
    @classmethod
    def _amount_strict_integer(cls, value: object) -> object:
        return reject_non_integer(value, "amount_minor_units")

    @field_validator("charged_at")
    @classmethod
    def _charged_at_aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "charged_at")


class ChargeView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    charge_id: SubscriptionChargeId
    tenant_id: TenantId
    subscription_id: SubscriptionId
    amount_minor_units: int
    currency: str
    charged_at: datetime
    recorded_by: str
    note: str | None
    created_at: datetime


class SubscriptionAnomalyQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    baseline_window: int = Field(default=DEFAULT_BASELINE_WINDOW, ge=1, le=MAX_BASELINE_WINDOW)


class SubscriptionAnomalyRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subscription_id: SubscriptionId
    subscription_name: str
    current_charge_cents: int
    baseline_avg_cents: float
    ratio: float | None
    code: Literal["SPEND_SPIKE", "NEW_SPENDER"]
    severity: Literal["info", "warning"]


class SubscriptionAnomalyReportView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_window: int
    anomalies: list[SubscriptionAnomalyRow]
    # Same versioned method tag D-012 uses (ADR-0021 Fork 1) — the underlying math is
    # identical (current value vs. a trailing average, ratio-thresholded); a future
    # different method gets a NEW literal, never a silent redefinition of this one.
    method: Literal["trailing_average_ratio_v1"] = "trailing_average_ratio_v1"
