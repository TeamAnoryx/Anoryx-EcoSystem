"""RBAC access-token API request/response DTOs (D-017, ADR-0017).

A deliberately bounded vertical slice: locally-issued, role-tagged bearer tokens
(two seeded roles — `tenant_admin`/`tenant_auditor`, mirroring Anoryx-Sentinel's own
already-shipped F-014/ADR-0017 role vocabulary for ecosystem naming consistency) —
not real SSO/OIDC/SAML (that is Sentinel's F-014, built for Sentinel's own admin
surface; federating Delta's admin console with it is explicitly out of scope for
this task, see ADR-0017 §3) and not a retrofit across every other D-007-D-016 admin
surface (also explicitly deferred).

Mirrors D-013/D-014/D-015/D-016's schema conventions throughout: `extra="forbid"`,
bounded free text with control-character rejection.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..identifiers import AccessTokenId, TenantId

AccessRole = Literal["tenant_admin", "tenant_auditor"]

_NAME_MAX_LENGTH = 256
_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _reject_control_chars(value: str, field_name: str) -> str:
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"{field_name} must not contain control characters (incl. newlines)")
    return value


class AccessTokenCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId
    name: str = Field(min_length=1, max_length=_NAME_MAX_LENGTH)
    role: AccessRole

    @field_validator("name")
    @classmethod
    def _name_no_control_chars(cls, value: str) -> str:
        return _reject_control_chars(value, "name")


class AccessTokenRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: TenantId


class AccessTokenView(BaseModel):
    """Never carries the raw token — only `AccessTokenIssuedView` (returned exactly
    once, at creation) does."""

    model_config = ConfigDict(extra="forbid")

    token_id: AccessTokenId
    tenant_id: TenantId
    name: str
    role: AccessRole
    created_at: datetime
    revoked_at: datetime | None


class AccessTokenIssuedView(AccessTokenView):
    """The one-time reveal of a newly-issued token's raw (unhashed) value — this is
    the ONLY response shape that ever carries it. It cannot be recovered later; a
    lost token must be revoked and a new one issued."""

    token: str
