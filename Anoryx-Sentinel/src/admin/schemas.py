"""Admin API request/response schemas (F-012a, ADR-0014).

All request bodies set extra="forbid" (R8): unknown fields are rejected, matching
the gateway's closed-input posture (no new unbounded input surface). String fields
are length-bounded to the underlying column widths.
"""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_AGENT_SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# --- Tenant lifecycle (STEP 3) ---------------------------------------------


_TENANT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class TenantCreateRequest(BaseModel):
    """Create-tenant body. name is required; display_name optional."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    display_name: str | None = Field(default=None, max_length=256)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not _TENANT_NAME_RE.match(v):
            raise ValueError("name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
        return v


class TenantResponse(BaseModel):
    """A tenant as returned by the admin API. Built from the ORM row."""

    model_config = ConfigDict(from_attributes=True)

    tenant_id: str
    name: str
    display_name: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime


class TenantListResponse(BaseModel):
    """A page of tenants (newest-first)."""

    tenants: list[TenantResponse]
    count: int


# --- Virtual key management (STEP 4) ---------------------------------------


class KeyMintRequest(BaseModel):
    """Mint-key body. The operator supplies the team/project/agent the key binds to.

    team_id / project_id must be existing UUIDs for the target tenant (enforced by
    FK + RLS at insert). agent_id is a lowercase slug. label is optional.
    """

    model_config = ConfigDict(extra="forbid")

    team_id: str = Field(max_length=64)
    project_id: str = Field(max_length=64)
    agent_id: str = Field(max_length=64)
    label: str | None = Field(default=None, max_length=256)
    expires_at: datetime | None = Field(default=None)

    @field_validator("team_id", "project_id")
    @classmethod
    def _uuid(cls, v: str) -> str:
        if not _UUID_RE.match(v):
            raise ValueError("must be a UUID")
        return v

    @field_validator("agent_id")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not _AGENT_SLUG_RE.match(v):
            raise ValueError("must be a lowercase slug")
        return v


class KeyResponse(BaseModel):
    """Key METADATA — never the fingerprint or secret (R4). Built from the ORM row."""

    model_config = ConfigDict(from_attributes=True)

    key_id: str
    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    label: str | None
    is_active: bool
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None


class KeyMintResponse(BaseModel):
    """Mint/rotate result. `secret` is the plaintext key, returned EXACTLY ONCE."""

    secret: str
    key: KeyResponse


class KeyListResponse(BaseModel):
    """A list of key metadata for a tenant."""

    keys: list[KeyResponse]
    count: int


# --- Audit-log read (STEP 5) -----------------------------------------------


class AuditEventResponse(BaseModel):
    """A single audit event — identity + chain metadata only (no payload dump).

    Built from the ORM row. Carries the four stable IDs, the event type/action,
    the correlation id, and the F-003 chain hashes (prev_hash/row_hash) so a
    reader can independently follow the chain.
    """

    model_config = ConfigDict(from_attributes=True)

    sequence_number: int
    event_id: str
    event_type: str
    event_timestamp: str
    request_id: str
    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    action_taken: str | None
    prev_hash: str
    row_hash: str


class AuditPageResponse(BaseModel):
    """A keyset page of audit events + honest F-003 chain verification status.

    next_cursor: pass back as after_sequence to fetch the next page (null = end).
    chain_verified / chain_rows_checked: the result of validate_chain() over the
    global F-003 hash chain (vector 11 — reported honestly, never fabricated).
    """

    events: list[AuditEventResponse]
    count: int
    next_cursor: int | None
    chain_verified: bool
    chain_rows_checked: int


# --- Operator control surface (STEP 6) -------------------------------------


class ConfigResponse(BaseModel):
    """A tenant's F-007/F-009 adjustable config. configured=False when no row exists."""

    tenant_id: str
    classifier_model_id: str | None
    audit_mode: str | None
    team_rpm_limit: int | None
    configured: bool


class ConfigUpdateRequest(BaseModel):
    """Bounded config adjust. Only provided fields are changed (model_fields_set).

    Validation mirrors the table's CHECK constraints; the DB is the source of truth
    and backstops at flush.
    """

    model_config = ConfigDict(extra="forbid")

    classifier_model_id: str | None = Field(default=None, max_length=128)
    audit_mode: str | None = Field(default=None, max_length=16)
    team_rpm_limit: int | None = Field(default=None)

    @field_validator("audit_mode")
    @classmethod
    def _audit_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in ("full", "redacted"):
            raise ValueError("audit_mode must be 'full' or 'redacted'")
        return v

    @field_validator("team_rpm_limit")
    @classmethod
    def _rpm(cls, v: int | None) -> int | None:
        if v is not None and v <= 0:
            raise ValueError("team_rpm_limit must be > 0")
        return v


class PolicyResponse(BaseModel):
    """Policy intake status (metadata projection)."""

    model_config = ConfigDict(from_attributes=True)

    policy_id: str
    policy_type: str
    current_version: int
    effective_from: datetime
    team_id: str
    project_id: str
    agent_id: str
    created_at: datetime


class PolicyListResponse(BaseModel):
    """A list of a tenant's current policies."""

    policies: list[PolicyResponse]
    count: int


class OperatorEvidenceRequest(BaseModel):
    """Operator compliance-evidence request for a target tenant (F-011 operator path)."""

    model_config = ConfigDict(extra="forbid")

    framework: str
    t0: str
    t1: str

    @field_validator("framework")
    @classmethod
    def _framework(cls, v: str) -> str:
        if v not in ("SOC2", "ISO27001"):
            raise ValueError("framework must be SOC2 or ISO27001")
        return v
