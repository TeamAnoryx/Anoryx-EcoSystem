"""Compliance test fixtures (F-011, ADR-0013).

Provides the DB session fixtures required by the DB-backed threat-model tests.
Intentionally does NOT re-export ensure_schema_at_head or
_provision_app_role_for_each_test — those autouse fixtures belong in the
persistence package and would block pure-unit compliance tests from running
even when Postgres is unavailable.

DB-backed tests (vectors 1, 4, 7, 10) require:
  - Live Postgres reachable via DATABASE_URL + APP_DATABASE_URL
  - SENTINEL_PROVISION_APP_ROLE=1

Pure unit tests (window validation) have no DB dependency and must run without
Postgres.
"""

from __future__ import annotations

import os
import re
import uuid
from typing import AsyncIterator

import pytest
import pytest_asyncio
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Load the root .env so DATABASE_URL / APP_DATABASE_URL are available.
_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


# ---------------------------------------------------------------------------
# Tenant identifiers
# ---------------------------------------------------------------------------


@pytest.fixture()
def test_tenant_id() -> str:
    """A stable, unique tenant_id for tenant-A in compliance tests."""
    return f"tenant-compliance-a-{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def tenant_b_id() -> str:
    """A distinct tenant_id for tenant-B (cross-tenant isolation tests)."""
    return f"tenant-compliance-b-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# DB URL fixtures (skip cleanly when env vars absent)
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        pytest.skip("DATABASE_URL not set — skipping DB-backed compliance test")
    return _to_asyncpg_url(raw)


@pytest.fixture()
def app_db_url() -> str:
    raw = os.environ.get("APP_DATABASE_URL", "")
    if not raw:
        pytest.skip("APP_DATABASE_URL not set — skipping DB-backed compliance test")
    return _to_asyncpg_url(raw)


# ---------------------------------------------------------------------------
# Privileged session (DATABASE_URL / BYPASSRLS) — used to SEED test rows
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def session(db_url: str) -> AsyncIterator[AsyncSession]:
    """Per-test privileged session for seeding rows (DATABASE_URL / BYPASSRLS)."""
    engine = create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    async with factory() as sess:
        async with sess.begin():
            nested = await sess.begin_nested()
            yield sess
            await nested.rollback()
    await engine.dispose()


# ---------------------------------------------------------------------------
# Tenant-scoped session (APP_DATABASE_URL / sentinel_app / NOBYPASSRLS)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def tenant_session(app_db_url: str, test_tenant_id: str) -> AsyncIterator[AsyncSession]:
    """Per-test RLS-scoped session (sentinel_app) for tenant-scoped reads."""
    engine = create_async_engine(app_db_url, pool_pre_ping=True, echo=False)
    factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    async with factory() as sess:
        async with sess.begin():
            await sess.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": test_tenant_id},
            )
            nested = await sess.begin_nested()
            yield sess
            await nested.rollback()
    await engine.dispose()


# ---------------------------------------------------------------------------
# Engine-cache reset (per test)
# ---------------------------------------------------------------------------
#
# persistence.database caches the app/privileged engines at module scope
# (_app_engine, _privileged_engine + their session factories). generate_evidence
# exercises the REAL cached get_tenant_session path, so a cached engine gets
# bound to the first test's event loop; under pytest-asyncio's per-function loop
# scope a later test runs in a fresh loop and the stale cached engine raises
# "Event loop is closed" during teardown. Dispose + null the caches after each
# test (within the still-open loop) so the next test rebuilds engines in its own
# loop. No-op for pure-unit tests (caches stay None).


# ---------------------------------------------------------------------------
# TRUNCATE teardown fixture (cross-tenant committed-row proofs ONLY)
#
# Why TRUNCATE instead of DELETE:
#   events_audit_log has a BEFORE DELETE trigger that blocks row-level DELETE
#   (append-only design).  TRUNCATE bypasses row-level triggers entirely, so it
#   is the only way to clean up committed rows in the test environment.
#
# Why scoped (NOT autouse, NOT global):
#   Only the three cross-tenant tests (vector 7, vector 8, cross-tenant endpoint)
#   COMMIT real rows across separate RLS connections to prove tenant-B data is
#   invisible to tenant-A.  Single-tenant tests use the no-commit savepoint
#   pattern and never pollute the table.  Keeping this fixture off autouse
#   ensures single-tenant tests never receive the teardown.
#
# Why safe:
#   This fixture operates against local dev/CI Postgres only — regenerated
#   each run.  No production data is ever present.
#
# Order-safety / genesis test:
#   Each of the three cross-tenant tests truncates in its OWN teardown, so the
#   committed window exists only for the duration of that test.  The table is
#   empty after teardown, satisfying test_single_event_first_row_uses_genesis_hash
#   (which asserts prev_hash == GENESIS_HASH, true only when the table is empty)
#   regardless of test ordering.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def truncate_audit_log_after() -> AsyncIterator[None]:
    """Yield, then TRUNCATE events_audit_log in teardown (privileged connection).

    Request this fixture ONLY from the three cross-tenant tests that commit
    real rows:
      - test_evidence_tenant_scoped (vector 7)
      - test_export_tenant_scoped   (vector 8)
      - test_cross_tenant_pack_request_denied

    Do NOT make this autouse — single-tenant no-commit tests must not receive it.
    """
    yield  # test body runs here

    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        return  # no DB → nothing to truncate (test was skipped earlier)
    url = _to_asyncpg_url(raw)
    engine = create_async_engine(
        url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    try:
        async with engine.begin() as conn:
            await conn.execute(text("TRUNCATE events_audit_log;"))
    finally:
        await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _reset_db_engine_caches() -> AsyncIterator[None]:
    yield
    import persistence.database as _db

    for _engine_attr, _factory_attr in (
        ("_app_engine", "_app_session_factory"),
        ("_privileged_engine", "_privileged_session_factory"),
    ):
        _engine = getattr(_db, _engine_attr, None)
        if _engine is not None:
            try:
                await _engine.dispose()
            except Exception:  # best-effort teardown; never fail a test on cleanup
                pass
        setattr(_db, _engine_attr, None)
        setattr(_db, _factory_attr, None)
