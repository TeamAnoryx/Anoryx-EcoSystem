"""R-005 tenant-isolation spine — RLS on the chat tables + the bind_membership DB invariant.

Direct, deterministic proofs (sync rendly_app sessions, the R-004 RLS test pattern) that the
storage half of tenant isolation holds independent of the WebSocket delivery half:

  * a rendly_app session scoped to tenant A reads ONLY tenant A's channels/messages;
  * an unset/empty tenant GUC collapses the NULLIF predicate to ZERO rows (fail-closed);
  * a forged tenant context cannot read another tenant's message even by id;
  * a cross-tenant membership is impossible at the DB (the same-tenant composite FK) AND at the
    app layer (bind_membership's ValueError).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from rendly.channel import Channel
from rendly.enums import ChannelRole, ChannelType, PresenceStatus
from rendly.membership import bind_membership
from rendly.persistence.chat_models import (
    ChannelRow,
    InspectionAuditLogRow,
    MembershipRow,
    MessageRow,
)
from rendly.persistence.database import _get_app_session_factory, get_tenant_session
from rendly.user import User

_NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


def _add_channel(tenant_id: str, channel_id: str, created_by: str) -> None:
    with get_tenant_session(tenant_id) as s:
        s.add(
            ChannelRow(
                tenant_id=tenant_id,
                channel_id=channel_id,
                name="c",
                type="private",
                source="manual",
                external_ref=None,
                created_by=created_by,
                created_at=_NOW,
                archived=False,
                next_seq=1,
            )
        )
        s.commit()


def _add_message(tenant_id: str, channel_id: str, message_id: str, sender: str) -> None:
    with get_tenant_session(tenant_id) as s:
        s.add(
            MessageRow(
                tenant_id=tenant_id,
                message_id=message_id,
                channel_id=channel_id,
                sender_user_id=sender,
                content="secret",
                content_type="text",
                seq=0,
                created_at=_NOW,
                prev_record_hash=None,
                content_hash=None,
                inspection_status="pass",
                inspection_evaluated_at=_NOW,
            )
        )
        s.commit()


def test_rls_scopes_channels_and_messages_to_the_guc_tenant(seed_user, new_uuid):
    ta, tb = new_uuid(), new_uuid()
    ua, ub = new_uuid(), new_uuid()
    ca, cb = new_uuid(), new_uuid()
    ma, mb = new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    seed_user(tenant_id=tb, user_id=ub)
    _add_channel(ta, ca, ua)
    _add_channel(tb, cb, ub)
    _add_message(ta, ca, ma, ua)
    _add_message(tb, cb, mb, ub)

    # Tenant A's session sees only A's channel + message.
    with get_tenant_session(ta) as s:
        chans = set(s.execute(select(ChannelRow.channel_id)).scalars().all())
        msgs = set(s.execute(select(MessageRow.message_id)).scalars().all())
    assert chans == {ca}
    assert msgs == {ma}

    # Tenant B's session sees only B's.
    with get_tenant_session(tb) as s:
        chans = set(s.execute(select(ChannelRow.channel_id)).scalars().all())
        msgs = set(s.execute(select(MessageRow.message_id)).scalars().all())
    assert chans == {cb}
    assert msgs == {mb}


def test_unset_guc_yields_zero_rows(seed_user, new_uuid):
    ta = new_uuid()
    ua, ca, ma = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    _add_channel(ta, ca, ua)
    _add_message(ta, ca, ma, ua)

    # A raw rendly_app session that never sets the GUC: NULLIF(current_setting(..,true),'') -> NULL
    # -> the predicate matches nothing (fail-closed).
    session = _get_app_session_factory()()
    try:
        chans = session.execute(select(ChannelRow.channel_id)).scalars().all()
        msgs = session.execute(select(MessageRow.message_id)).scalars().all()
    finally:
        session.close()
    assert chans == []
    assert msgs == []


def test_forged_tenant_cannot_read_another_tenants_message_by_id(seed_user, new_uuid):
    ta, tb = new_uuid(), new_uuid()
    ua, ub = new_uuid(), new_uuid()
    cb, mb = new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    seed_user(tenant_id=tb, user_id=ub)
    _add_channel(tb, cb, ub)
    _add_message(tb, cb, mb, ub)

    # Tenant A's session, knowing B's message id, still reads zero rows (RLS, not app logic).
    with get_tenant_session(ta) as s:
        row = s.execute(
            select(MessageRow.message_id).where(MessageRow.message_id == mb)
        ).scalar_one_or_none()
    assert row is None


def test_cross_tenant_membership_rejected_at_db_layer(seed_user, new_uuid):
    """A membership joining a channel and a user from different tenants is impossible at the DB."""
    ta, tb = new_uuid(), new_uuid()
    ua, ub = new_uuid(), new_uuid()
    ca = new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    seed_user(tenant_id=tb, user_id=ub)
    _add_channel(ta, ca, ua)

    # Try to insert (tenant=A, channel=CA, user=UB): RLS WITH CHECK passes (tenant matches the GUC),
    # but the composite FK fk_memberships_user needs a (A, UB) users row — UB is in tenant B — so
    # the insert is rejected. Cross-tenant membership is structurally unconstructible.
    with pytest.raises(IntegrityError):
        with get_tenant_session(ta) as s:
            s.add(
                MembershipRow(
                    tenant_id=ta,
                    channel_id=ca,
                    user_id=ub,  # foreign tenant's user
                    role="member",
                    added_at=_NOW,
                )
            )
            s.commit()


def test_cross_tenant_membership_rejected_at_app_layer(new_uuid):
    """bind_membership refuses a cross-tenant (user, channel) pair before any DB work."""
    ta, tb = new_uuid(), new_uuid()
    user_b = User(
        user_id=new_uuid(),
        tenant_id=tb,
        display_name="B",
        status_text=None,
        presence=PresenceStatus.ONLINE,
        created_at=_NOW,
    )
    channel_a = Channel(
        channel_id=new_uuid(),
        tenant_id=ta,
        name="a",
        type=ChannelType.PRIVATE,
        created_by=new_uuid(),
        created_at=_NOW,
    )
    with pytest.raises(ValueError, match="cross-tenant"):
        bind_membership(user_b, channel_a, role=ChannelRole.MEMBER, added_at=_NOW)


def test_load_inspection_audit_log_returns_newest_first_scoped_to_tenant(seed_user, new_uuid):
    """chat_repo.load_inspection_audit_log (R-008): newest-first, RLS-scoped, metadata only.

    Exercises the async write+read pair directly (asyncio.run, mirroring
    ``test_async_get_tenant_session_is_fail_closed_on_blank_tenant`` below) since there is no
    REST surface over this yet (ADR-0008 Fork B: the admin read endpoint is deferred).
    """
    import asyncio
    from datetime import timedelta

    from rendly.persistence import chat_repo
    from rendly.persistence.async_database import get_tenant_session as async_tenant_session
    from rendly.realtime.inspector import DetectorFinding

    ta, tb = new_uuid(), new_uuid()
    ua, ub = new_uuid(), new_uuid()
    ca, cb = new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    seed_user(tenant_id=tb, user_id=ub)
    _add_channel(ta, ca, ua)
    _add_channel(tb, cb, ub)

    older, newer = new_uuid(), new_uuid()

    async def _write_and_read() -> list[dict]:
        async with async_tenant_session(ta) as s:
            await chat_repo.insert_inspection_audit(
                s,
                audit_id=older,
                tenant_id=ta,
                channel_id=ca,
                sender_user_id=ua,
                status="blocked",
                detectors=(DetectorFinding(category="pii", outcome="block"),),
                evaluated_at=_NOW,
                created_at=_NOW,
            )
            await chat_repo.insert_inspection_audit(
                s,
                audit_id=newer,
                tenant_id=ta,
                channel_id=ca,
                sender_user_id=ua,
                status="seam_unavailable",
                detectors=(),
                evaluated_at=_NOW + timedelta(seconds=1),
                created_at=_NOW + timedelta(seconds=1),
            )
            await s.commit()
        async with async_tenant_session(tb) as s:
            await chat_repo.insert_inspection_audit(
                s,
                audit_id=new_uuid(),
                tenant_id=tb,
                channel_id=cb,
                sender_user_id=ub,
                status="blocked",
                detectors=(),
                evaluated_at=_NOW,
                created_at=_NOW,
            )
            await s.commit()
        async with async_tenant_session(ta) as s:
            return await chat_repo.load_inspection_audit_log(s, tenant_id=ta)

    rows = asyncio.run(_write_and_read())
    assert [r["audit_id"] for r in rows] == [newer, older]  # newest first
    assert rows[0]["status"] == "seam_unavailable"
    assert rows[0]["detectors"] == ()
    assert rows[1]["status"] == "blocked"
    assert rows[1]["detectors"] == (DetectorFinding(category="pii", outcome="block"),)


def test_async_get_tenant_session_is_fail_closed_on_blank_tenant():
    """The ASYNC get_tenant_session refuses to open without a tenant context (rule-6 fail-closed).

    Mirrors the sync layer's guard on the new async engine: a blank/whitespace tenant raises BEFORE
    any session opens, so no async chat statement can ever run without a tenant GUC.
    """
    import asyncio

    from rendly.persistence.async_database import TenantContextRequiredError, get_tenant_session

    async def _open_blank() -> None:
        async with get_tenant_session("   ") as _session:
            pass  # pragma: no cover - never reached; the guard raises first

    with pytest.raises(TenantContextRequiredError):
        asyncio.run(_open_blank())


def _add_inspection_audit(tenant_id: str, channel_id: str, audit_id: str, sender: str) -> None:
    with get_tenant_session(tenant_id) as s:
        s.add(
            InspectionAuditLogRow(
                tenant_id=tenant_id,
                audit_id=audit_id,
                channel_id=channel_id,
                sender_user_id=sender,
                status="blocked",
                detectors=[{"category": "pii", "outcome": "block"}],
                evaluated_at=_NOW,
                created_at=_NOW,
            )
        )
        s.commit()


def test_inspection_audit_log_scoped_to_guc_tenant(seed_user, new_uuid):
    """R-008: inspection_audit_log RLS mirrors messages' — a tenant sees only its own incidents."""
    ta, tb = new_uuid(), new_uuid()
    ua, ub = new_uuid(), new_uuid()
    ca, cb = new_uuid(), new_uuid()
    aa, ab = new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    seed_user(tenant_id=tb, user_id=ub)
    _add_channel(ta, ca, ua)
    _add_channel(tb, cb, ub)
    _add_inspection_audit(ta, ca, aa, ua)
    _add_inspection_audit(tb, cb, ab, ub)

    with get_tenant_session(ta) as s:
        ids = set(s.execute(select(InspectionAuditLogRow.audit_id)).scalars().all())
    assert ids == {aa}

    with get_tenant_session(tb) as s:
        ids = set(s.execute(select(InspectionAuditLogRow.audit_id)).scalars().all())
    assert ids == {ab}


def test_rendly_app_cannot_update_or_delete_inspection_audit_log(seed_user, new_uuid):
    """inspection_audit_log is APPEND-ONLY by grant — same posture as messages, no R-009 chain."""
    ta = new_uuid()
    ua, ca, aa = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    _add_channel(ta, ca, ua)
    _add_inspection_audit(ta, ca, aa, ua)

    with get_tenant_session(ta) as s:
        with pytest.raises(Exception):  # noqa: B017 - psycopg raises a permission error on UPDATE
            s.execute(
                text(
                    "UPDATE rendly.inspection_audit_log SET status='seam_unavailable' WHERE audit_id=:a"
                ),
                {"a": aa},
            )
            s.commit()
    with get_tenant_session(ta) as s:
        with pytest.raises(Exception):  # noqa: B017 - and on DELETE
            s.execute(text("DELETE FROM rendly.inspection_audit_log WHERE audit_id=:a"), {"a": aa})
            s.commit()


def test_rendly_app_cannot_update_or_delete_messages(seed_user, new_uuid):
    """messages are APPEND-ONLY by grant — rendly_app has no UPDATE/DELETE (immutability is R-009)."""
    ta = new_uuid()
    ua, ca, ma = new_uuid(), new_uuid(), new_uuid()
    seed_user(tenant_id=ta, user_id=ua)
    _add_channel(ta, ca, ua)
    _add_message(ta, ca, ma, ua)

    with get_tenant_session(ta) as s:
        with pytest.raises(Exception):  # noqa: B017 - psycopg raises a permission error on UPDATE
            s.execute(
                text("UPDATE rendly.messages SET content='tampered' WHERE message_id=:m"), {"m": ma}
            )
            s.commit()
    with get_tenant_session(ta) as s:
        with pytest.raises(Exception):  # noqa: B017 - and on DELETE
            s.execute(text("DELETE FROM rendly.messages WHERE message_id=:m"), {"m": ma})
            s.commit()
