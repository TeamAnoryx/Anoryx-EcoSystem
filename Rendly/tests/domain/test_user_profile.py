"""User matches the LOCKED wire shape; Profile is the internal affiliation superset."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.enums import OrgRole, PresenceStatus
from rendly.profile import Profile, bind_profile
from rendly.user import User

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)
_T = "12121212-1212-4212-8212-121212121212"
_U = "13131313-1313-4313-8313-131313131313"


def _user(**over: object) -> User:
    base: dict[str, object] = {
        "user_id": _U,
        "tenant_id": _T,
        "display_name": "Alex",
        "presence": PresenceStatus.ONLINE,
        "created_at": _NOW,
    }
    base.update(over)
    return User(**base)


def test_user_minimal_valid_status_text_defaults_null():
    u = _user()
    assert u.status_text is None
    assert u.presence is PresenceStatus.ONLINE


def test_user_busy_presence_accepted():
    # The LOCKED enum is 4-value incl. 'busy' (R-001 wins over the dispatch's 3).
    assert _user(presence=PresenceStatus.BUSY).presence is PresenceStatus.BUSY


def test_user_rejects_bad_presence():
    with pytest.raises(ValidationError):
        _user(presence="dnd")


def test_user_rejects_extra_key():
    # No team/role/department on the wire User — those live on Profile (FORK E).
    with pytest.raises(ValidationError):
        _user(department="x")


def test_user_status_text_bounded():
    with pytest.raises(ValidationError):
        _user(status_text="x" * 257)


def test_profile_org_role_and_team():
    p = bind_profile(_user(), org_role=OrgRole.ADMIN)
    assert p.org_role is OrgRole.ADMIN
    assert p.team is None


def test_profile_rejects_owner_org_role():
    # OrgRole has no 'owner' — org ownership is not an MVP concept (FORK B).
    with pytest.raises(ValidationError):
        Profile(user_id=_U, tenant_id=_T, org_role="owner")


def test_profile_rejects_extra_key():
    with pytest.raises(ValidationError):
        Profile(user_id=_U, tenant_id=_T, org_role=OrgRole.MEMBER, intent_vector="x")


def test_profile_rejects_empty_team():
    # Absence of a team is None, not "" — an empty affiliation slug is rejected.
    with pytest.raises(ValidationError):
        Profile(user_id=_U, tenant_id=_T, org_role=OrgRole.MEMBER, team="")
