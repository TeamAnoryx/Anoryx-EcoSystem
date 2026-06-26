"""Closed enumerations for the Rendly domain.

Every enum value below is reconciled with R-001's LOCKED wire contract — the
contract is the law and these values match it byte-for-byte:

- ``PresenceStatus`` == ``contracts/openapi.yaml`` ``User.presence`` AND
  ``contracts/messages.schema.json`` ``presence_status`` (FOUR values).
- ``ChannelType`` == ``Channel.type`` (``public | private | dm``).
- ``ChannelSource`` == ``Channel.source`` (``manual | delta_team``) — the reserved
  Delta-team auto-mapping seam (R-006 / D-016); R-001 always emits ``manual``.
- ``ChannelRole`` == ``Membership.role`` (channel-level RBAC).

``OrgRole`` is NOT on R-001's wire (the token ``roles`` claim is an open string
array): it is the per-tenant org-level role (FORK B = B1, fixed enum). It is part
of the internal ``Profile`` superset (FORK E = E1) and is never serialized through
R-001's closed ``User`` shape.

Using ``StrEnum`` makes each member serialize to its plain string value, so a
``model_dump(mode="json")`` payload matches the wire/schema enum strings exactly.
"""

from __future__ import annotations

from enum import StrEnum


class PresenceStatus(StrEnum):
    """User presence. Matches the LOCKED 4-value wire enum (incl. ``busy``)."""

    ONLINE = "online"
    AWAY = "away"
    BUSY = "busy"
    OFFLINE = "offline"


class ChannelType(StrEnum):
    """Channel visibility/kind. Matches the LOCKED ``Channel.type`` enum."""

    PUBLIC = "public"
    PRIVATE = "private"
    DM = "dm"


class ChannelSource(StrEnum):
    """Channel provenance. ``manual`` is the only value R-001 ever creates;
    ``delta_team`` is the RESERVED Delta-team auto-mapping seam (R-006 / D-016)."""

    MANUAL = "manual"
    DELTA_TEAM = "delta_team"


class ChannelRole(StrEnum):
    """Per-channel RBAC role. Matches the LOCKED ``Membership.role`` enum."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"


class OrgRole(StrEnum):
    """Per-tenant org-level role (FORK B = B1, fixed enum; NOT on R-001's wire).

    Distinct axis from ``ChannelRole``: this is the org membership role that drives
    role-based channels (R-005 / R-006). There is deliberately no ``owner`` — org
    ownership is not an MVP concept; ``owner`` is a per-channel role only.
    """

    ADMIN = "admin"
    MEMBER = "member"
    GUEST = "guest"
