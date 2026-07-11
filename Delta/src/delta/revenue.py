"""Revenue records (X-005: Delta RECORDS a source product's real monetization event).

``RevenueRecord`` mirrors ``delta-financial.schema.json`` ``RevenueIngestRecord`` after the
server has resolved ``source_product`` from the authenticated caller: it carries the tenant,
the monetization event class, the OPAQUE source tier (recorded verbatim, never interpreted),
the integer-cents amount, an optional currency, the source-supplied idempotency key, and the
source's ``occurred_at``.

``source_product`` is SERVER-RESOLVED from the authenticated caller (the holder of the
dedicated revenue-ingest HMAC secret), NEVER read from the request body — v1 accepts only
``rendly``, so it is the module constant :data:`REVENUE_SOURCE_PRODUCT` here (the O-010 / X-004
source_product discipline). It is therefore not a request field.

Money is INTEGER minor units (cents) ONLY. ``amount_cents`` is validated as a TRUE ``int``
(``float`` and ``bool`` rejected) — it is NEVER routed through the float-accepting
``Money.from_wire_cents``, because this field is contractually integer, not an estimate.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from .identifiers import TenantId
from .money import (
    DEFAULT_CURRENCY,
    MAX_MONEY_MINOR_UNITS,
    Currency,
    bounded_count,
    require_aware_utc,
)

# v1 accepts EXACTLY one source product. The dedicated revenue-ingest HMAC secret
# IDENTIFIES the authenticated caller as Rendly, so source_product is resolved in code and
# NEVER read from the request body (revenue_source_product; the O-010/X-004 discipline).
REVENUE_SOURCE_PRODUCT = "rendly"

_TIER_MAX_LENGTH = 64
# The source product's monetization tier name — opaque to Delta, recorded verbatim.
RevenueTier = Annotated[str, StringConstraints(min_length=1, max_length=_TIER_MAX_LENGTH)]

# Source-supplied dedup key (revenue_idempotency_key): unique per source_product.
_IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9._:-]{1,128}$"
_IDEMPOTENCY_KEY_MAX_LENGTH = 128
RevenueIdempotencyKey = Annotated[
    str,
    StringConstraints(pattern=_IDEMPOTENCY_KEY_PATTERN, max_length=_IDEMPOTENCY_KEY_MAX_LENGTH),
]


class RevenueEventType(StrEnum):
    """The monetization event class (RevenueEventType).

    v1 POSTS a balanced ledger transaction for ``subscription_granted`` ONLY.
    ``subscription_revoked`` is durably ACCEPTED but does NOT reverse or void the granting
    transaction — automatic revocation/reversal posting is DEFERRED X-005 follow-up scope.
    """

    SUBSCRIPTION_GRANTED = "subscription_granted"
    SUBSCRIPTION_REVOKED = "subscription_revoked"


class RevenueRecord(BaseModel):
    """A validated X-005 monetization record (the RevenueIngestRecord shape, resolved).

    Frozen + ``extra="forbid"`` (the D-001 discipline). ``source_product`` is not a field
    here — it is the fixed :data:`REVENUE_SOURCE_PRODUCT` server-resolved from the caller.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: TenantId
    event_type: RevenueEventType
    tier: RevenueTier
    amount_cents: int
    currency: Currency = DEFAULT_CURRENCY
    idempotency_key: RevenueIdempotencyKey
    occurred_at: datetime

    @field_validator("amount_cents", mode="before")
    @classmethod
    def _amount(cls, value: object) -> int:
        # Integer minor units ONLY — reject float/bool/str explicitly (no coercion), bounded
        # to the 1e11 Money ceiling. This is Delta: money is never a float (vectors 1, 3).
        return bounded_count(value, "amount_cents", MAX_MONEY_MINOR_UNITS)

    @field_validator("occurred_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "occurred_at")
