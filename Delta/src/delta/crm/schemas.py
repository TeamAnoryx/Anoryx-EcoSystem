"""Unified CRM API request/response DTOs (D-013, ADR-0013).

A deliberately bounded vertical slice: client records, a deal pipeline, an interaction
history, and a stakeholder roster — not full enterprise-CRM feature parity (no custom
fields, no email/calendar integration, no multi-currency FX; see ADR-0013 §3).

Mirrors D-007's `allocation_admin.schemas` conventions throughout: `extra="forbid"`
everywhere, bounded free-text fields with control-character rejection (log-injection
guard), `require_aware_utc` on every caller-supplied timestamp.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..identifiers import ClientId, DealId, InteractionId, StakeholderId, TenantId
from ..money import DEFAULT_CURRENCY, Currency, require_aware_utc

DealStage = Literal["lead", "qualified", "proposal", "negotiation", "won", "lost"]
_TERMINAL_STAGES: frozenset[str] = frozenset({"won", "lost"})

InteractionType = Literal["call", "email", "meeting", "note"]
StakeholderRole = Literal["decision_maker", "influencer", "champion", "blocker", "unknown"]

# Bounded free-text fields (mirrors allocation_admin.schemas' storage-bloat +
# log-injection discipline).
_NAME_MAX_LENGTH = 256
_CONTACT_NAME_MAX_LENGTH = 256
_ACTOR_MAX_LENGTH = 128
_SUMMARY_MAX_LENGTH = 2048
_EMAIL_MAX_LENGTH = 320  # RFC 5321 practical bound
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
# Permissive shape check only — no email-validator dependency in this codebase, so
# this is NOT strict RFC 5322 validation, just a bounded sanity check + control-char
# guard. Never treated as proof of deliverability.
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

# A deal value is capped at the same order of magnitude as a Delta budget cap
# (delta.money.MAX_BUDGET_COST_CENTS) — a deal is a business record, not a ledger
# entry, so it does not reuse that exact constant, but an unbounded BigInteger input
# from an admin caller should still be rejected rather than silently accepted.
MAX_DEAL_VALUE_MINOR_UNITS = 100_000_000_000  # 1e11 minor units (mirrors MAX_BUDGET_COST_CENTS)

# List-response bounds (same discipline as D-007/D-008/D-011/D-012's own caps).
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


class ClientCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    primary_contact_name: str | None = Field(default=None, max_length=_CONTACT_NAME_MAX_LENGTH)
    primary_contact_email: str | None = Field(default=None, max_length=_EMAIL_MAX_LENGTH)

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")

    @field_validator("primary_contact_name")
    @classmethod
    def _contact_name_no_control_chars(cls, value: str | None) -> str | None:
        return None if value is None else _reject_control_chars(value, "primary_contact_name")

    @field_validator("primary_contact_email")
    @classmethod
    def _contact_email_shape(cls, value: str | None) -> str | None:
        return _validate_email(value, "primary_contact_email")


class ClientView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: ClientId
    tenant_id: TenantId
    name: str
    primary_contact_name: str | None
    primary_contact_email: str | None
    created_at: datetime
    updated_at: datetime


class DealCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    value_minor_units: int | None = Field(default=None, ge=0, le=MAX_DEAL_VALUE_MINOR_UNITS)
    currency: Currency | None = DEFAULT_CURRENCY
    expected_close_date: datetime | None = None

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")

    @field_validator("expected_close_date")
    @classmethod
    def _expected_close_date_aware(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value, "expected_close_date")


class DealStageTransitionRequest(BaseModel):
    """Move a deal to a new stage. Rejected once the deal is already 'won'/'lost'
    (ADR-0013 Fork 2 — terminal stages are immutable outcomes, mirrors D-007's
    allocation-decision idempotency guard)."""

    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    stage: DealStage
    actor: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("actor")
    @classmethod
    def _actor_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "actor")


class DealView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deal_id: DealId
    client_id: ClientId
    tenant_id: TenantId
    name: str
    stage: DealStage
    value_minor_units: int | None
    currency: Currency | None
    expected_close_date: datetime | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class InteractionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    deal_id: DealId | None = None
    stakeholder_id: StakeholderId | None = None
    interaction_type: InteractionType
    occurred_at: datetime
    summary: str = Field(min_length=1, max_length=_SUMMARY_MAX_LENGTH)
    created_by: str = Field(min_length=1, max_length=_ACTOR_MAX_LENGTH)

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at_aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "occurred_at")

    @field_validator("summary")
    @classmethod
    def _summary_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "summary")

    @field_validator("created_by")
    @classmethod
    def _created_by_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "created_by")


class InteractionView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interaction_id: InteractionId
    client_id: ClientId
    deal_id: DealId | None
    stakeholder_id: StakeholderId | None
    tenant_id: TenantId
    interaction_type: InteractionType
    occurred_at: datetime
    summary: str
    created_by: str
    created_at: datetime


class StakeholderCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    deal_id: DealId | None = None
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    role: StakeholderRole = "unknown"
    email: str | None = Field(default=None, max_length=_EMAIL_MAX_LENGTH)

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")

    @field_validator("email")
    @classmethod
    def _email_shape(cls, value: str | None) -> str | None:
        return _validate_email(value, "email")


class StakeholderView(BaseModel):
    """`interaction_count`/`last_interaction_at` are the "automated" part of stakeholder
    mapping (ADR-0013 Fork 3) — computed live from `interactions` explicitly TAGGED to
    this stakeholder's id (never matched by name, never derived from free-text NLP
    extraction). `last_interaction_at` is None when no interaction has been tagged to
    this stakeholder yet."""

    model_config = ConfigDict(extra="forbid")

    stakeholder_id: StakeholderId
    client_id: ClientId
    deal_id: DealId | None
    tenant_id: TenantId
    name: str
    role: StakeholderRole
    email: str | None
    created_at: datetime
    updated_at: datetime
    interaction_count: int
    last_interaction_at: datetime | None


class RelationshipScoreView(BaseModel):
    """A deterministic recency + frequency heuristic — NOT a trained/validated
    statistical or ML model (ADR-0013 Fork 1, same honesty-boundary discipline as
    D-011's `current_rate_projection_v1` and D-012's `trailing_average_ratio_v1`)."""

    model_config = ConfigDict(extra="forbid")

    client_id: ClientId
    score: float = Field(ge=0.0, le=100.0)
    interaction_count_90d: int
    days_since_last_interaction: int | None
    open_deal_count: int
    method: Literal["recency_frequency_v1"] = "recency_frequency_v1"


class ClientDetailView(BaseModel):
    """Composed view for a client's detail page — one round trip for the whole
    picture (client + deals + recent interactions + stakeholders + score), mirroring
    D-012's `ChargebackForWindow`-style "one request, several joined views" shape on
    the frontend side."""

    model_config = ConfigDict(extra="forbid")

    client: ClientView
    deals: list[DealView]
    recent_interactions: list[InteractionView]
    stakeholders: list[StakeholderView]
    relationship_score: RelationshipScoreView
