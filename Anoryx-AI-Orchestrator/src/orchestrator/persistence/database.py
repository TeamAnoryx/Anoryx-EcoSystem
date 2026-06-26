"""Database engines + session factories for the Orchestrator (O-003, ADR-0003).

Ported from Anoryx-Sentinel/src/persistence/database.py (F-003b Option α): two
physically separate engines, each bound to a distinct Postgres role, so RLS isolation
is structural rather than application-enforced.

TWO ENGINES, TWO URLs (both must be present in the environment):
  ORCH_DATABASE_URL      — privileged role (owner / BYPASSRLS). Used for: hash-chain
                           ops (append + validate on the GLOBAL ingest_audit_log chain),
                           Alembic migrations, admin/break-glass. Never serves ordinary
                           tenant request traffic.
  ORCH_APP_DATABASE_URL  — orchestrator_app role (LOGIN, NOSUPERUSER, NOBYPASSRLS,
                           NOCREATEDB, NOCREATEROLE). Used for: all tenant-scoped writes
                           (ingest_events, dead_letter_queue, forward_outbox). Every
                           checkout sets the transaction-local GUC app.current_tenant_id
                           before any tenant query runs.

Neither URL nor any credential is ever logged or printed.

DOUBLE-BEGIN DISCIPLINE (ADR-0026, ported verbatim in intent):
  get_tenant_session() runs set_config(...) BEFORE it yields, which AUTOBEGINS a
  transaction. Callers MUST NOT wrap it in `async with session.begin()` — that raises
  sqlalchemy.exc.InvalidRequestError ("a transaction is already begun"), the double-begin
  class that a broad `except` silently swallows into a fail-open control. Read/write
  directly on the autobegun transaction; commit explicitly for writes.
  get_privileged_session() does NOT set a GUC and does NOT autobegin, so chain ops use
  `async with session.begin()` there (the correct place).
"""

from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

#: The non-privileged application login role (NOBYPASSRLS). A session connecting as
#: this role MUST NOT be used for chain ops.
ORCHESTRATOR_APP_ROLE: str = "orchestrator_app"


class TenantContextRequiredError(RuntimeError):
    """Raised by get_tenant_session() when tenant_id is missing/empty/whitespace.

    Hard fail-closed guard: no tenant session opens without a valid tenant context. The
    caller supplies tenant_id sourced from the SERVER-RESOLVED, schema-validated payload
    (payload.tenant_id) — never from a client-supplied header.
    """


def _to_asyncpg_url(raw: str) -> str:
    """Convert a sync/psycopg postgres URL to asyncpg form. Never logs the URL."""
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _privileged_database_url() -> str:
    raw = os.environ.get("ORCH_DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "ORCH_DATABASE_URL is not set. This is the privileged (owner/BYPASSRLS) "
            "connection used for migrations and global ingest-audit chain ops."
        )
    return _to_asyncpg_url(raw)


def _app_database_url() -> str:
    raw = os.environ.get("ORCH_APP_DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "ORCH_APP_DATABASE_URL is not set. This is the orchestrator_app "
            "(NOBYPASSRLS) connection used for all tenant-scoped ingest writes."
        )
    return _to_asyncpg_url(raw)


def _connect_args() -> dict[str, object]:
    """asyncpg connect args. ORCH_DB_SSL controls TLS to the DB:

    unset / "negotiate"  → asyncpg default (probe SSL, fall back to plaintext);
    "disable"/"off"/"false"/"0" → ssl=False (no SSL probe). Local/CI Postgres has SSL off,
        and on Windows asyncpg's SSL-probe fallback can raise ConnectionResetError, so
        CI/local sets ORCH_DB_SSL=disable. Production sets its own TLS policy (deploy/O-008).
    """
    mode = os.environ.get("ORCH_DB_SSL", "").strip().lower()
    if mode in ("disable", "off", "false", "0"):
        return {"ssl": False}
    return {}


def _pool_kwargs(pool_size: int, max_overflow: int) -> dict[str, object]:
    """Pooling kwargs. ORCH_DB_NULLPOOL=1 → NullPool (no connection reuse).

    NullPool opens a fresh connection per checkout and closes it on return — robust in
    flaky per-function-event-loop test environments (notably asyncpg on Windows, where a
    pooled connection can be reset between checkouts). Production leaves it unset and uses
    a real pool with pre-ping. NullPool does not accept pool_size/max_overflow.
    """
    if os.environ.get("ORCH_DB_NULLPOOL", "").strip().lower() in ("1", "true", "on", "yes"):
        from sqlalchemy.pool import NullPool

        return {"poolclass": NullPool}
    return {"pool_size": pool_size, "max_overflow": max_overflow, "pool_pre_ping": True}


# ---------------------------------------------------------------------------
# Lazy module-level engine singletons. reset_engines() disposes + nulls them so a
# test (per-event-loop, asyncio_mode=auto) rebuilds a fresh engine from the current
# env in its own loop — reset at SETUP, not only teardown, so a stale DSN from a prior
# test/package cannot pollute this one (ADR-0026 / F-007 lesson).
# ---------------------------------------------------------------------------

_privileged_engine: object | None = None
_privileged_session_factory: async_sessionmaker | None = None
_app_engine: object | None = None
_app_session_factory: async_sessionmaker | None = None


def _get_privileged_engine():  # type: ignore[return]
    global _privileged_engine
    if _privileged_engine is None:
        from sqlalchemy.ext.asyncio import create_async_engine

        _privileged_engine = create_async_engine(
            _privileged_database_url(),
            echo=False,
            connect_args=_connect_args(),
            **_pool_kwargs(pool_size=2, max_overflow=3),
        )
    return _privileged_engine


def _get_privileged_session_factory() -> async_sessionmaker:
    global _privileged_session_factory
    if _privileged_session_factory is None:
        _privileged_session_factory = async_sessionmaker(
            bind=_get_privileged_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
    return _privileged_session_factory


def _get_app_engine():  # type: ignore[return]
    global _app_engine
    if _app_engine is None:
        from sqlalchemy.ext.asyncio import create_async_engine

        _app_engine = create_async_engine(
            _app_database_url(),
            echo=False,
            connect_args=_connect_args(),
            **_pool_kwargs(pool_size=5, max_overflow=10),
        )
    return _app_engine


def _get_app_session_factory() -> async_sessionmaker:
    global _app_session_factory
    if _app_session_factory is None:
        _app_session_factory = async_sessionmaker(
            bind=_get_app_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
    return _app_session_factory


async def reset_engines() -> None:
    """Dispose + null both engine singletons (call at test setup AND teardown).

    A cached engine binds to the event loop of first use; under per-function loops a
    stale pool would hit 'Event loop is closed' or a stale-DSN host. Resetting forces a
    fresh engine bound to the current loop/env.
    """
    global _privileged_engine, _privileged_session_factory, _app_engine, _app_session_factory
    for engine in (_privileged_engine, _app_engine):
        if engine is not None:
            try:
                await engine.dispose()
            except Exception:  # noqa: S110 - best-effort dispose; never mask the test
                pass
    _privileged_engine = None
    _privileged_session_factory = None
    _app_engine = None
    _app_session_factory = None


@asynccontextmanager
async def get_privileged_session() -> AsyncIterator[AsyncSession]:
    """Privileged session (ORCH_DATABASE_URL / owner / BYPASSRLS).

    WHEN TO USE: global ingest_audit_log chain ops (append, validate) and migrations.
    NEVER for ordinary tenant request traffic. Does NOT autobegin — chain ops open their
    own `async with session.begin()` here (the correct place for an explicit begin).
    """
    factory = _get_privileged_session_factory()
    async with factory() as session:
        yield session


@asynccontextmanager
async def get_tenant_session(tenant_id: str) -> AsyncIterator[AsyncSession]:
    """Tenant-scoped session (ORCH_APP_DATABASE_URL / orchestrator_app / NOBYPASSRLS).

    FAIL-CLOSED: raises TenantContextRequiredError BEFORE opening a transaction if
    tenant_id is missing/empty/whitespace. tenant_id MUST come from the server-resolved,
    schema-validated payload.tenant_id — never a client header.

    AUTOBEGIN: set_config(..., is_local=true) runs before the yield, so the session is
    already in a (transaction-local GUC) transaction. NEVER wrap the body in
    `session.begin()` (double-begin fail-open, ADR-0026). Read/write directly; commit
    explicitly for writes. The GUC is SET LOCAL — it reverts at transaction end, so it
    cannot leak across pool-reused connections; RLS predicates collapse an unset/empty
    GUC to zero rows (fail-closed), never widening scope.
    """
    if not tenant_id or not tenant_id.strip():
        raise TenantContextRequiredError(
            "tenant_id must be a non-empty string sourced from the validated "
            "payload.tenant_id. get_tenant_session refuses to open without a tenant "
            "context (fail-closed)."
        )
    factory = _get_app_session_factory()
    async with factory() as session:
        await session.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": tenant_id},
        )
        yield session
