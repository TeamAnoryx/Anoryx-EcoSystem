"""Membership — the User <-> Channel relation, tenant- and role-scoped.

Matches R-001's LOCKED ``components.schemas.Membership``
(``contracts/openapi.yaml``): ``{channel_id, tenant_id, user_id, role, added_at}``,
closed, ``role`` the channel-level RBAC enum.

THE TENANT-ISOLATION INVARIANT (R-001's HIGH finding becomes a domain property):
a membership's ``tenant_id`` MUST equal BOTH the user's and the channel's
``tenant_id`` — there is no cross-tenant membership. R-001 enforced this at runtime
via tenant-scoped 404 resolution.

The flat ``Membership`` record holds only opaque ids (not the parent ``User`` /
``Channel`` objects), so — unlike Delta D-001's ``Transaction``, which EMBEDS its
entries and can therefore reject a mismatched entry inside a ``@model_validator`` —
``Membership`` cannot self-validate tenant agreement at the model level. The
invariant is instead enforced by the canonical construction path
:func:`bind_membership`: it takes the real ``User`` and ``Channel``, rejects a
cross-tenant pair, and derives every id from the validated parents. A cross-tenant
membership is therefore unconstructible **via the binding factory**.

Direct ``Membership(...)`` with hand-supplied ids is a deliberate lower-level
primitive that is NOT tenant-validated — it is reserved for R-004 rehydrating an
already-tenant-scoped DB row (where the RLS predicate, not this layer, is the
boundary). All application code that mints a new membership MUST use
:func:`bind_membership`. See ADR-0002 §7.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from .channel import Channel
from .common import require_aware_utc
from .enums import ChannelRole
from .identifiers import ChannelId, TenantId, UserId
from .user import User


class Membership(BaseModel):
    """A user's membership of a channel, with a channel-level RBAC role. Immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    channel_id: ChannelId
    tenant_id: TenantId
    user_id: UserId
    role: ChannelRole
    added_at: datetime

    @field_validator("added_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "added_at")


def bind_membership(
    user: User,
    channel: Channel,
    *,
    role: ChannelRole,
    added_at: datetime,
) -> Membership:
    """Build a ``Membership`` from a real ``User`` + ``Channel`` (the canonical path).

    Rejects a cross-tenant pair: if ``user.tenant_id != channel.tenant_id`` the
    membership is REFUSED (``ValueError``) and nothing is constructed. On a valid
    same-tenant pair, every id — including ``tenant_id`` — is read from the
    validated parents, so the resulting membership's tenant agrees with both the
    user and the channel by construction, not by a later check.
    """
    if user.tenant_id != channel.tenant_id:
        raise ValueError("cross-tenant membership rejected: user.tenant_id != channel.tenant_id")
    return Membership(
        channel_id=channel.channel_id,
        tenant_id=channel.tenant_id,
        user_id=user.user_id,
        role=role,
        added_at=added_at,
    )
