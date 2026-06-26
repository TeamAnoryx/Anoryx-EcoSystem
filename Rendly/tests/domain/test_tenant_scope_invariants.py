"""The spine: cross-tenant isolation is a STRUCTURAL property of the domain.

Proves with REAL objects (no stubs): a cross-tenant Membership is REJECTED and a
valid same-tenant one is ACCEPTED. This is R-001's HIGH finding (no cross-tenant
membership) made structural — the same property Delta D-001 enforces on a
Transaction's entries.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.enums import ChannelRole, OrgRole
from rendly.membership import Membership, bind_membership
from rendly.profile import bind_profile

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)
_T1 = "11111111-1111-4111-8111-111111111111"
_T2 = "22222222-2222-4222-8222-222222222222"


def test_bind_membership_rejects_cross_tenant(make_user, make_channel):
    # REAL objects: a user in tenant T1, a channel in tenant T2.
    user = make_user(tenant_id=_T1)
    channel = make_channel(tenant_id=_T2)
    with pytest.raises(ValueError, match="cross-tenant"):
        bind_membership(user, channel, role=ChannelRole.MEMBER, added_at=_NOW)


def test_bind_membership_accepts_same_tenant(make_user, make_channel):
    # REAL accept: a user and channel in the same tenant bind to a valid membership.
    user = make_user(tenant_id=_T1)
    channel = make_channel(tenant_id=_T1)
    m = bind_membership(user, channel, role=ChannelRole.OWNER, added_at=_NOW)
    assert isinstance(m, Membership)
    assert m.tenant_id == _T1
    assert m.user_id == user.user_id
    assert m.channel_id == channel.channel_id
    assert m.role is ChannelRole.OWNER


def test_bind_profile_derives_tenant_from_user(make_user):
    # A profile's tenant is read FROM the user — it cannot disagree by this path.
    user = make_user(tenant_id=_T1)
    p = bind_profile(user, org_role=OrgRole.MEMBER, team="platform")
    assert p.tenant_id == _T1
    assert p.user_id == user.user_id
    assert p.org_role is OrgRole.MEMBER
    assert p.team == "platform"


def test_membership_is_frozen(make_user, make_channel):
    # Immutable: a constructed membership cannot be re-pointed to another tenant.
    user = make_user(tenant_id=_T1)
    channel = make_channel(tenant_id=_T1)
    m = bind_membership(user, channel, role=ChannelRole.MEMBER, added_at=_NOW)
    with pytest.raises(ValidationError):
        m.tenant_id = _T2


def test_membership_rejects_extra_key():
    # Closed shape: a smuggled key is rejected (no silent extra channel).
    with pytest.raises(ValidationError):
        Membership(
            channel_id="14141414-1414-4414-8414-141414141414",
            tenant_id=_T1,
            user_id="13131313-1313-4313-8313-131313131313",
            role=ChannelRole.MEMBER,
            added_at=_NOW,
            smuggled="x",
        )


def test_direct_membership_construction_is_an_unguarded_primitive():
    # DOCUMENTED, INTENTIONAL: the flat Membership record holds only ids and does
    # NOT model-validate tenant agreement (it has no @model_validator) — direct
    # construction with mismatched ids SUCCEEDS. The tenant-equality invariant is
    # enforced exclusively by bind_membership (see the two tests above). This
    # primitive is reserved for R-004 rehydrating an already-tenant-scoped row,
    # where RLS — not this layer — is the boundary. See ADR-0002 §7.
    m = Membership(
        channel_id="14141414-1414-4414-8414-141414141414",  # a tenant-T1 channel
        tenant_id=_T2,  # ... stamped with tenant T2 ...
        user_id="13131313-1313-4313-8313-131313131313",  # ... and a tenant-? user
        role=ChannelRole.MEMBER,
        added_at=_NOW,
    )
    assert m.tenant_id == _T2  # no model-level rejection — by design; mint via bind_membership
