"""D-017 non-stubbed RBAC persistence suite: real store writes -> real SQL reads,
real RLS. Mirrors ``tests/capacity/test_store_db.py``'s shape.
"""

from __future__ import annotations

from datetime import datetime, timezone

from delta.persistence.database import get_tenant_session
from delta.rbac import store

from .conftest import db_required

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)


@db_required
async def test_create_and_get_token_roundtrip(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_token(
            session,
            tenant_id=tenant_id,
            name="CI viewer key",
            role="tenant_auditor",
            token_hash="a" * 64,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        fetched = await store.get_token(session, token_id=created.token_id)

    assert fetched is not None
    assert fetched.name == "CI viewer key"
    assert fetched.role == "tenant_auditor"
    assert fetched.revoked_at is None


@db_required
async def test_revoke_token_sets_revoked_at(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        token = await store.create_token(
            session,
            tenant_id=tenant_id,
            name="Key",
            role="tenant_admin",
            token_hash="b" * 64,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        await store.revoke_token(session, token_id=token.token_id, now=_NOW)
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        revoked = await store.get_token(session, token_id=token.token_id)
    assert revoked is not None
    assert revoked.revoked_at == _NOW


@db_required
async def test_get_active_token_by_hash_finds_active_token(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        await store.create_token(
            session,
            tenant_id=tenant_id,
            name="Key",
            role="tenant_auditor",
            token_hash="c" * 64,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        found = await store.get_active_token_by_hash(session, token_hash="c" * 64)
    assert found is not None
    assert found.role == "tenant_auditor"


@db_required
async def test_get_active_token_by_hash_excludes_revoked_token(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        token = await store.create_token(
            session,
            tenant_id=tenant_id,
            name="Key",
            role="tenant_admin",
            token_hash="d" * 64,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        await store.revoke_token(session, token_id=token.token_id, now=_NOW)
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        found = await store.get_active_token_by_hash(session, token_hash="d" * 64)
    assert found is None


@db_required
async def test_get_active_token_by_hash_no_match_returns_none(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        found = await store.get_active_token_by_hash(session, token_hash="e" * 64)
    assert found is None


@db_required
async def test_list_tokens_orders_newest_first(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        await store.create_token(
            session,
            tenant_id=tenant_id,
            name="Older",
            role="tenant_auditor",
            token_hash="f" * 64,
            now=datetime(2026, 7, 1, tzinfo=timezone.utc),
        )
        await session.commit()
    async with get_tenant_session(tenant_id) as session:
        await store.create_token(
            session,
            tenant_id=tenant_id,
            name="Newer",
            role="tenant_auditor",
            token_hash="1" * 64,
            now=datetime(2026, 7, 5, tzinfo=timezone.utc),
        )
        await session.commit()

    async with get_tenant_session(tenant_id) as session:
        rows = await store.list_tokens(session)
    assert [r.name for r in rows] == ["Newer", "Older"]


@db_required
async def test_cross_tenant_isolation_tokens_invisible_to_other_tenant(
    tenant_id, other_tenant_id
) -> None:
    async with get_tenant_session(tenant_id) as session:
        created = await store.create_token(
            session,
            tenant_id=tenant_id,
            name="Key",
            role="tenant_admin",
            token_hash="2" * 64,
            now=_NOW,
        )
        await session.commit()

    async with get_tenant_session(other_tenant_id) as session:
        fetched = await store.get_token(session, token_id=created.token_id)
        listed = await store.list_tokens(session)
        by_hash = await store.get_active_token_by_hash(session, token_hash="2" * 64)

    assert fetched is None
    assert listed == []
    assert by_hash is None
