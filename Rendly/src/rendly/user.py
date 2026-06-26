"""User — end-user/employee identity, the wire-projection shape.

This is the canonical persistent identity and is the EXACT shape R-001 surfaces as
``components.schemas.User`` in ``contracts/openapi.yaml`` (closed object, same
fields, same bounds, same required set). R-004 persists it; R-003 issues the
OAuth2 + JWT token whose ``sub`` claim carries this ``user_id``.

The richer affiliation fields (org role, team) live on the internal ``Profile``
superset (FORK E = E1), NOT here — keeping ``User`` byte-compatible with the
locked wire shape. ``user_id`` is an opaque surrogate, never PII (``ids.md``).

FORK A = A1: ``User`` is tenant-local; ``tenant_id`` is the only ecosystem join.
The O-010 unified-identity seam (``idp_subject``) stays where R-001 put it — a
token claim (R-003's concern) — and is deliberately NOT a field on this entity.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from .common import require_aware_utc
from .enums import PresenceStatus
from .identifiers import TenantId, UserId

# Bounds mirror contracts/openapi.yaml User exactly.
DisplayName = Annotated[str, StringConstraints(max_length=128)]
StatusText = Annotated[str, StringConstraints(max_length=256)]


class User(BaseModel):
    """A tenant-local user identity. Immutable; matches the LOCKED wire ``User``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    display_name: DisplayName
    status_text: StatusText | None = None
    presence: PresenceStatus
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "created_at")
