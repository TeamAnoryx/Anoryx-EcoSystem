"""Rendly internal domain model (R-002).

The canonical, storage-agnostic persistent entities + their invariants that
R-001's wire contract serializes and that R-004 will persist. Cross-tenant
isolation is a STRUCTURAL property of these types (see
:func:`rendly.membership.bind_membership`), not a runtime check.

No server, no persistence, no DDL — those are R-003 / R-004.
"""

from __future__ import annotations

from .channel import Channel
from .enums import ChannelRole, ChannelSource, ChannelType, OrgRole, PresenceStatus
from .identifiers import ChannelId, TenantId, UserId
from .membership import Membership, bind_membership
from .profile import Profile, bind_profile
from .tenant import Tenant
from .user import User

__all__ = [
    "Channel",
    "ChannelId",
    "ChannelRole",
    "ChannelSource",
    "ChannelType",
    "Membership",
    "OrgRole",
    "PresenceStatus",
    "Profile",
    "Tenant",
    "TenantId",
    "User",
    "UserId",
    "bind_membership",
    "bind_profile",
]
