"""RLS isolation tests for SSO identity tables (F-014 STEP 2).

Empirical proof (ADR-0017 §12.1 cross-tenant proof pattern, vector 3):

  Two tenants (A and B) have admin_user rows committed to the DB.
  A session scoped to tenant A via get_tenant_session() must return:
    - Tenant A's own admin_user row (visible).
    - Zero rows for tenant B's admin_user row (invisible due to RLS).

This test file uses two independent DB connections:
  1. A privileged session (DATABASE_URL / BYPASSRLS) to insert setup rows
     and commit them so RLS-scoped connections can see the data.
  2. The `tenant_session` fixture (APP_DATABASE_URL / sentinel_app / NOBYPASSRLS)
     scoped to tenant A's UUID — this is where RLS is enforced.

NOTE: The privileged `session` fixture uses SAVEPOINT and rolls back at teardown.
The commit-then-cleanup pattern below uses a separate engine connection that commits
within the test body and then deletes the inserted rows to leave the DB clean.
This mirrors the approach used in test_audit_chain.py for tamper tests.

All tests are skipped (not failed) when DATABASE_URL or APP_DATABASE_URL is absent
or when the DB is unreachable — following the skip-not-fail pattern from the suite.
"""

from __future__ import annotations

import os
import re
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ---------------------------------------------------------------------------
# Skip guard — absence of DB URL skips the whole module, does not fail.
# ---------------------------------------------------------------------------

_DB_URL = os.environ.get("DATABASE_URL", "")
_APP_DB_URL = os.environ.get("APP_DATABASE_URL", "")

if not _DB_URL or not _APP_DB_URL:
    pytest.skip(
        "DATABASE_URL or APP_DATABASE_URL not set — skipping RLS isolation tests",
        allow_module_level=True,
    )


def _make_async_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


_PRIV_URL = _make_async_url(_DB_URL)
_APP_URL = _make_async_url(_APP_DB_URL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _uid() -> str:
    return str(uuid.uuid4())


async def _commit_admin_user(
    priv_url: str,
    tenant_id: str,
    idp_subject: str,
) -> str:
    """Insert and COMMIT an admin_user row via a privileged connection.

    Returns the new admin_user row id (UUID string).
    A separate privileged connection is used so the row is visible across
    independent connections (the SAVEPOINT-scoped `session` fixture is
    not committed and therefore not visible to separate connections).

    id and tenant_id are VARCHAR(64) — passed as plain strings to match
    the column type (no uuid.UUID() conversion needed or desired).
    """
    engine = create_async_engine(
        priv_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    factory = async_sessionmaker(
        bind=engine, expire_on_commit=False, autoflush=False, autocommit=False
    )
    row_id = str(uuid.uuid4())

    async with factory() as sess:
        async with sess.begin():
            # Ensure the tenant row exists first (FK constraint).
            await sess.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, is_active) "
                    "VALUES (:tid, :name, true) ON CONFLICT (tenant_id) DO NOTHING"
                ),
                {"tid": tenant_id, "name": "RLS-test " + tenant_id[:8]},
            )
            # Columns are VARCHAR(64) — pass strings directly.
            await sess.execute(
                text(
                    "INSERT INTO admin_users "
                    "  (id, tenant_id, idp_subject, is_active, created_at) "
                    "VALUES "
                    "  (:id, :tenant_id, :subject, true, now())"
                ),
                {
                    "id": row_id,
                    "tenant_id": tenant_id,
                    "subject": idp_subject,
                },
            )
    # Session committed on __aexit__ of sess.begin().
    await engine.dispose()
    return row_id


async def _delete_admin_user(priv_url: str, row_id: str) -> None:
    """Delete a committed admin_user row (cleanup after test)."""
    engine = create_async_engine(
        priv_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    factory = async_sessionmaker(
        bind=engine, expire_on_commit=False, autoflush=False, autocommit=False
    )
    async with factory() as sess:
        async with sess.begin():
            # id is VARCHAR(64) — pass as string.
            await sess.execute(
                text("DELETE FROM admin_users WHERE id = :id"),
                {"id": row_id},
            )
    await engine.dispose()


async def _delete_tenant(priv_url: str, tenant_id: str) -> None:
    engine = create_async_engine(
        priv_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    factory = async_sessionmaker(
        bind=engine, expire_on_commit=False, autoflush=False, autocommit=False
    )
    async with factory() as sess:
        async with sess.begin():
            # tenant_id is VARCHAR(64) — pass as string.
            await sess.execute(
                text("DELETE FROM tenants WHERE tenant_id = :tid"),
                {"tid": tenant_id},
            )
    await engine.dispose()


# ---------------------------------------------------------------------------
# Tenant A session fixture (scoped to tenant_a_id for this test module)
# ---------------------------------------------------------------------------


@pytest.fixture
def tenant_a_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def tenant_b_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def test_tenant_id(tenant_a_id: str) -> str:
    """Required by the conftest tenant_session fixture — routes it to tenant A."""
    return tenant_a_id


# ---------------------------------------------------------------------------
# RLS isolation tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_user_rls_own_tenant_visible(
    tenant_session: AsyncSession,
    tenant_a_id: str,
) -> None:
    """Tenant A session can read its own admin_user row."""
    row_id = await _commit_admin_user(
        _PRIV_URL,
        tenant_a_id,
        "sub|rls-own",
    )
    try:
        result = await tenant_session.execute(
            text("SELECT id FROM admin_users WHERE id = :id"),
            {"id": row_id},
        )
        rows = result.fetchall()
        assert len(rows) == 1, (
            f"Expected tenant A to see its own admin_user row, got {rows}. "
            "RLS may be denying own-tenant reads."
        )
    finally:
        await _delete_admin_user(_PRIV_URL, row_id)
        await _delete_tenant(_PRIV_URL, tenant_a_id)


@pytest.mark.asyncio
async def test_admin_user_rls_cross_tenant_invisible(
    tenant_session: AsyncSession,
    tenant_a_id: str,
    tenant_b_id: str,
) -> None:
    """Tenant A session CANNOT see tenant B's admin_user row (vector 3).

    This is the empirical cross-tenant proof required by ADR-0017 §12.1.
    The tenant_session fixture is scoped to tenant_a_id, so RLS predicate
    is:  tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
    Tenant B's row has tenant_id = tenant_b_id, so it must be invisible.
    """
    row_b_id = await _commit_admin_user(
        _PRIV_URL,
        tenant_b_id,
        "sub|rls-b",
    )
    try:
        result = await tenant_session.execute(
            text("SELECT id FROM admin_users WHERE id = :id"),
            {"id": row_b_id},
        )
        rows = result.fetchall()
        msg = (
            f"Cross-tenant SELECT on admin_users returned {rows}. "  # noqa: S608
            "RLS is NOT isolating tenant B from tenant A. "
            "Check that migration 0014 applied ENABLE ROW LEVEL SECURITY + FORCE "
            "and the tenant_isolation policy USING predicate is correct."
        )
        assert rows == [], msg
    finally:
        await _delete_admin_user(_PRIV_URL, row_b_id)
        await _delete_tenant(_PRIV_URL, tenant_b_id)


@pytest.mark.asyncio
async def test_admin_user_rls_two_tenants_independent(
    tenant_session: AsyncSession,
    tenant_a_id: str,
    tenant_b_id: str,
) -> None:
    """Tenant A session sees its own row and zero rows for tenant B simultaneously.

    This is the full two-tenant proof: both rows exist in the DB, but the
    RLS-scoped query returns exactly one (tenant A's own) row.
    """
    row_a_id = await _commit_admin_user(_PRIV_URL, tenant_a_id, "sub|rls-a")
    row_b_id = await _commit_admin_user(_PRIV_URL, tenant_b_id, "sub|rls-b-full")
    try:
        # Query for both IDs — tenant session should return only row A.
        # id is VARCHAR(64) — pass strings directly.
        result = await tenant_session.execute(
            text("SELECT id FROM admin_users WHERE id = :id_a OR id = :id_b"),
            {"id_a": row_a_id, "id_b": row_b_id},
        )
        visible_ids = {row[0] for row in result.fetchall()}
        assert (
            row_a_id in visible_ids
        ), "Tenant A's own admin_user row was not visible in its own session."
        assert row_b_id not in visible_ids, (
            f"Tenant B's admin_user row was visible in tenant A's session. "
            f"RLS isolation is NOT working on admin_users. "
            f"visible_ids={visible_ids!r}"
        )
    finally:
        await _delete_admin_user(_PRIV_URL, row_a_id)
        await _delete_admin_user(_PRIV_URL, row_b_id)
        await _delete_tenant(_PRIV_URL, tenant_a_id)
        await _delete_tenant(_PRIV_URL, tenant_b_id)
