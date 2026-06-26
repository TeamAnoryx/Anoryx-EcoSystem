"""Tenant — the organization boundary and the isolation scoping root.

R-001 exposes no ``Tenant`` resource on the wire (``tenant_id`` travels as the
server-resolved join key on every other resource). The domain still needs a
minimal root aggregate to anchor the tenant-isolation invariant that the other
entities are scoped against. It is deliberately minimal (no tenant name — nothing
on the wire needs one; YAGNI).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from .common import require_aware_utc
from .identifiers import TenantId


class Tenant(BaseModel):
    """An organization boundary. Immutable; ``tenant_id`` is the ecosystem join key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: TenantId
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "created_at")
