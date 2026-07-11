"""R-030: the public-embed grant + public-safe manifest projection seam
(public_embed.py), composing R-013's event.py and R-027's platform_rbac.py."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from rendly.enums import OrgRole
from rendly.event import Event, EventSession, bind_event, schedule_session
from rendly.profile import Profile
from rendly.public_embed import (
    MAX_EMBED_GRANT_LIFETIME,
    MAX_MANIFEST_SESSIONS,
    EmbedGrant,
    is_grant_active,
    issue_embed_grant,
    render_embed_manifest,
)
from rendly.tenant import Tenant

_NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)
_TENANT_ID = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT_ID = "99999999-9999-4999-8999-999999999999"
_HOST_ID = "11111111-1111-4111-8111-111111111111"
_GRANT_ID = "33333333-3333-4333-8333-333333333333"


def _tenant(tenant_id: str = _TENANT_ID) -> Tenant:
    return Tenant(tenant_id=tenant_id, created_at=_NOW)


def _profile(org_role: OrgRole = OrgRole.MEMBER, tenant_id: str = _TENANT_ID) -> Profile:
    return Profile(user_id=_HOST_ID, tenant_id=tenant_id, org_role=org_role)


def _event(tenant_id: str = _TENANT_ID) -> Event:
    host = Profile(user_id=_HOST_ID, tenant_id=tenant_id, org_role=OrgRole.ADMIN)
    return bind_event(host, title="Q3 Product Summit", created_at=_NOW)


def _window(start_offset_min: int, duration_min: int = 30) -> tuple[datetime, datetime]:
    start = _NOW + timedelta(minutes=start_offset_min)
    return start, start + timedelta(minutes=duration_min)


_ADMIN = _profile(OrgRole.ADMIN)
_MEMBER = _profile(OrgRole.MEMBER)


def _grant(event: Event, *, lifetime: timedelta = timedelta(days=1)) -> EmbedGrant:
    return issue_embed_grant(_tenant(), _ADMIN, event, issued_at=_NOW, expires_at=_NOW + lifetime)


# --- EmbedGrant construction / bounded lifetime -------------------------------------------------


def test_embed_grant_rejects_naive_issued_at():
    with pytest.raises(ValidationError):
        EmbedGrant(
            grant_id=_GRANT_ID,
            tenant_id=_TENANT_ID,
            event_id=_event().event_id,
            issued_at=datetime(2026, 7, 11, 12, 0, 0),  # naive
            expires_at=_NOW + timedelta(days=1),
        )


def test_embed_grant_rejects_expires_before_issued():
    with pytest.raises(ValidationError, match="expires_at must be strictly after issued_at"):
        EmbedGrant(
            grant_id=_GRANT_ID,
            tenant_id=_TENANT_ID,
            event_id=_event().event_id,
            issued_at=_NOW,
            expires_at=_NOW - timedelta(minutes=1),
        )


def test_embed_grant_rejects_lifetime_beyond_the_ceiling():
    with pytest.raises(ValidationError, match="expires_at must be within"):
        EmbedGrant(
            grant_id=_GRANT_ID,
            tenant_id=_TENANT_ID,
            event_id=_event().event_id,
            issued_at=_NOW,
            expires_at=_NOW + MAX_EMBED_GRANT_LIFETIME + timedelta(seconds=1),
        )


def test_embed_grant_accepts_lifetime_at_the_ceiling():
    grant = EmbedGrant(
        grant_id=_GRANT_ID,
        tenant_id=_TENANT_ID,
        event_id=_event().event_id,
        issued_at=_NOW,
        expires_at=_NOW + MAX_EMBED_GRANT_LIFETIME,
    )
    assert grant.expires_at == _NOW + MAX_EMBED_GRANT_LIFETIME


def test_embed_grant_is_frozen():
    grant = _grant(_event())
    with pytest.raises(ValidationError):
        grant.expires_at = _NOW + timedelta(days=2)  # type: ignore[misc]


def test_embed_grant_rejects_extra_key():
    with pytest.raises(ValidationError):
        EmbedGrant(
            grant_id=_GRANT_ID,
            tenant_id=_TENANT_ID,
            event_id=_event().event_id,
            issued_at=_NOW,
            expires_at=_NOW + timedelta(days=1),
            scope="anything",
        )


# --- issue_embed_grant: the permission-gated authorization path ---------------------------------


def test_issue_embed_grant_mints_new_grant_bound_to_event():
    event = _event()
    grant = _grant(event)
    assert grant.event_id == event.event_id
    assert grant.tenant_id == event.tenant_id
    assert grant.issued_at == _NOW


def test_issue_embed_grant_requires_the_permission():
    with pytest.raises(PermissionError, match="MANAGE_TENANT_CHANNELS"):
        issue_embed_grant(
            _tenant(), _MEMBER, _event(), issued_at=_NOW, expires_at=_NOW + timedelta(days=1)
        )


def test_issue_embed_grant_rejects_cross_tenant_actor():
    other_tenant_admin = Profile(
        user_id="55555555-5555-4555-8555-555555555555",
        tenant_id=_OTHER_TENANT_ID,
        org_role=OrgRole.ADMIN,
    )
    with pytest.raises(ValueError, match="cross-tenant actor"):
        issue_embed_grant(
            _tenant(),
            other_tenant_admin,
            _event(),
            issued_at=_NOW,
            expires_at=_NOW + timedelta(days=1),
        )


def test_issue_embed_grant_rejects_cross_tenant_event():
    event = _event(tenant_id=_OTHER_TENANT_ID)
    with pytest.raises(ValueError, match="cross-tenant event"):
        issue_embed_grant(
            _tenant(), _ADMIN, event, issued_at=_NOW, expires_at=_NOW + timedelta(days=1)
        )


# --- is_grant_active --------------------------------------------------------------------------


def test_is_grant_active_true_within_window():
    grant = _grant(_event(), lifetime=timedelta(days=1))
    assert is_grant_active(grant, as_of=_NOW + timedelta(hours=1)) is True


def test_is_grant_active_false_before_issued_at():
    grant = _grant(_event(), lifetime=timedelta(days=1))
    assert is_grant_active(grant, as_of=_NOW - timedelta(seconds=1)) is False


def test_is_grant_active_false_at_or_after_expiry():
    grant = _grant(_event(), lifetime=timedelta(days=1))
    assert is_grant_active(grant, as_of=grant.expires_at) is False


# --- render_embed_manifest: the public-safe projection ------------------------------------------


def _session(
    event: Event, existing: tuple[EventSession, ...] = (), *, offset=0, duration=30, title="Keynote"
):
    starts_at, ends_at = _window(offset, duration)
    return schedule_session(event, existing, title=title, starts_at=starts_at, ends_at=ends_at)


def test_render_embed_manifest_projects_title_and_agenda_only():
    event = _event()
    grant = _grant(event)
    first = _session(event, title="Opening Keynote")
    second = _session(event, (first,), offset=60, title="Roadmap AMA")

    manifest = render_embed_manifest(grant, event, (second, first), as_of=_NOW)

    assert manifest.grant_id == grant.grant_id
    assert manifest.event_title == event.title
    assert [s.title for s in manifest.sessions] == ["Opening Keynote", "Roadmap AMA"]
    assert manifest.sessions[0].starts_at == first.starts_at
    assert manifest.sessions[0].ends_at == first.ends_at


def test_render_embed_manifest_excludes_internal_identifiers():
    event = _event()
    grant = _grant(event)
    manifest = render_embed_manifest(grant, event, (), as_of=_NOW)
    dumped = manifest.model_dump()
    assert "tenant_id" not in dumped
    assert "event_id" not in dumped
    assert "host_id" not in dumped


def test_render_embed_manifest_rejects_grant_for_a_different_event():
    event = _event()
    other_event = _event()
    grant = _grant(event)
    with pytest.raises(ValueError, match="grant does not name this event"):
        render_embed_manifest(grant, other_event, (), as_of=_NOW)


def test_render_embed_manifest_rejects_expired_grant():
    event = _event()
    grant = _grant(event, lifetime=timedelta(hours=1))
    with pytest.raises(PermissionError, match="not active at as_of"):
        render_embed_manifest(grant, event, (), as_of=grant.expires_at)


def test_render_embed_manifest_rejects_not_yet_active_grant():
    event = _event()
    grant = _grant(event, lifetime=timedelta(days=1))
    with pytest.raises(PermissionError, match="not active at as_of"):
        render_embed_manifest(grant, event, (), as_of=_NOW - timedelta(seconds=1))


def test_render_embed_manifest_rejects_a_session_from_a_different_event():
    event = _event()
    other_event = _event()
    grant = _grant(event)
    foreign_session = _session(other_event, title="Foreign")
    with pytest.raises(ValueError, match="cross-event session"):
        render_embed_manifest(grant, event, (foreign_session,), as_of=_NOW)


def test_render_embed_manifest_rejects_oversized_session_list():
    event = _event()
    grant = _grant(event, lifetime=timedelta(days=1))
    sessions: tuple[EventSession, ...] = ()
    for i in range(9):
        sessions = (*sessions, _session(event, sessions, offset=i * 30, title=f"S{i}"))
    with pytest.raises(ValueError, match="must not exceed"):
        render_embed_manifest(grant, event, sessions * 6, as_of=_NOW)  # 54 > MAX_MANIFEST_SESSIONS


def test_max_manifest_sessions_is_reasonable():
    assert MAX_MANIFEST_SESSIONS == 50
