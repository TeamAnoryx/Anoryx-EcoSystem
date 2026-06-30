"""ASYNC database engines + session factories for the Rendly chat runtime (R-005).

ADR-0004 Fork D drew the forward boundary verbatim: *"When R-005's chat runtime needs async
DB access (WebSockets), it adds its OWN async session layer alongside this one; the
RLS/role/GUC design is driver-agnostic and ports directly."* This module is that async layer
(FORK A = A1). It runs ALONGSIDE the merged SYNC ``database.py`` — it does NOT replace it:
R-003/R-004's REST auth keeps the sync psycopg engine; only the new WebSocket/chat code (and
the R-005 chat REST routes) use this async asyncpg engine.

It reads the SAME two env URLs as the sync layer (``DATABASE_URL`` owner / ``APP_DATABASE_URL``
rendly_app), rewriting each to the asyncpg driver. The RLS contract is identical to 0001/0002:
the privileged engine bypasses RLS (admin/migrations-adjacent), the app engine is rendly_app
(NOBYPASSRLS) and every tenant checkout sets the transaction-local GUC ``app.current_tenant_id``.

DOUBLE-BEGIN DISCIPLINE (banked rule 6 — the F-007/F-009/F-018 fail-open class, now on fresh
async code): :func:`get_tenant_session` runs ``set_config(...)`` BEFORE it yields, which
AUTOBEGINS the transaction. Callers MUST NOT wrap the body in ``async with session.begin()`` —
that raises the double-begin error a broad ``except`` can swallow into a fail-OPEN control.
Read/write directly on the autobegun transaction; commit explicitly for writes.

Neither URL nor any credential is ever logged or printed.
"""

from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from . import RENDLY_APP_ROLE, TENANT_GUC  # noqa: F401  (re-export anchors / docs)
from .database import TenantContextRequiredError  # reuse the one fail-closed error type

__all__ = [
    "TenantContextRequiredError",
    "get_tenant_session",
    "reset_async_engines",
]

# NOTE: R-005's async chat layer needs ONLY the tenant (rendly_app / NOBYPASSRLS) engine — every
# chat read/write is tenant-scoped under RLS. The privileged (owner / BYPASSRLS) path is sync-only
# in R-005 (migrations + provisioning), so no async privileged engine is built here (YAGNI + a
# smaller surface — no unused BYPASSRLS engine). A future task that needs async privileged access
# (e.g. R-009 hash-chain ops) adds a focused one then, mirroring the sync `database.py`.


def _to_asyncpg_url(raw: str) -> str:
    """Rewrite a postgres URL to the asyncpg driver form. Never logged.

    ``postgresql://`` and ``postgresql+psycopg://`` both become ``postgresql+asyncpg://`` so
    the same env URL the sync layer / migrations use also drives the async engine.
    """
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _app_database_url() -> str:
    raw = os.environ.get("APP_DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "APP_DATABASE_URL is not set. This is the rendly_app (NOBYPASSRLS) connection used "
            "for all tenant-scoped chat traffic. See Rendly/docker-compose.yml."
        )
    return _to_asyncpg_url(raw)


def _connect_args() -> dict[str, object]:
    """asyncpg connect args. ``RENDLY_DB_SSL`` controls TLS to the DB:

    unset / "negotiate"  → asyncpg default (probe SSL, fall back to plaintext);
    "disable"/"off"/"false"/"0" → ``ssl=False`` (no SSL probe). Local + CI Postgres run SSL
        off, and on Windows asyncpg's SSL-probe fallback can raise ConnectionResetError, so
        local/CI set ``RENDLY_DB_SSL=disable`` (mirrors the Orchestrator ``ORCH_DB_SSL`` fix).
        Production sets its own TLS policy at deploy time (R-010).
    """
    mode = os.environ.get("RENDLY_DB_SSL", "").strip().lower()
    if mode in ("disable", "off", "false", "0"):
        return {"ssl": False}
    return {}


def _pool_kwargs(pool_size: int, max_overflow: int) -> dict[str, object]:
    """Pooling kwargs. ``RENDLY_DB_NULLPOOL=1`` → NullPool (no connection reuse).

    NullPool opens a fresh connection per checkout and closes it on return — robust in flaky
    per-function-event-loop test environments (notably asyncpg on Windows, where a pooled
    connection can be reset between checkouts). Production leaves it unset and uses a real pool
    with pre-ping. NullPool does not accept pool_size/max_overflow.
    """
    if os.environ.get("RENDLY_DB_NULLPOOL", "").strip().lower() in ("1", "true", "on", "yes"):
        from sqlalchemy.pool import NullPool

        return {"poolclass": NullPool}
    return {"pool_size": pool_size, "max_overflow": max_overflow, "pool_pre_ping": True}


# ---------------------------------------------------------------------------
# Lazy module-level async engine singletons. reset_async_engines() disposes + nulls them so
# a test (per-event-loop) rebuilds a fresh engine bound to its own loop — reset at SETUP, not
# only teardown, so a stale DSN/loop from a prior test or package cannot pollute this one
# (banked rule 7; the F-019 cached-engine lesson, now for the async engine).
# ---------------------------------------------------------------------------

_app_engine: object | None = None
_app_session_factory: async_sessionmaker | None = None


def _get_app_engine():  # type: ignore[no-untyped-def]
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


async def reset_async_engines() -> None:
    """Dispose + null the async app-engine singleton (call at test SETUP and teardown).

    A cached async engine binds to the event loop of first use; under per-function loops a
    stale pool hits 'Event loop is closed' or a stale-DSN host. Resetting forces a fresh
    engine bound to the current loop/env (banked rule 7).
    """
    global _app_engine, _app_session_factory
    if _app_engine is not None:
        try:
            await _app_engine.dispose()
        except Exception:  # noqa: BLE001, S110 - best-effort dispose; never mask the test
            pass
    _app_engine = None
    _app_session_factory = None


@asynccontextmanager
async def get_tenant_session(tenant_id: str) -> AsyncIterator[AsyncSession]:
    """Tenant-scoped async session (APP_DATABASE_URL / rendly_app / NOBYPASSRLS).

    FAIL-CLOSED: raises :class:`TenantContextRequiredError` BEFORE opening a transaction if
    ``tenant_id`` is missing/empty/whitespace. ``tenant_id`` MUST come from the server-resolved
    JWT claims (``AccessTokenClaims.tenant_id``) — never from a client-supplied frame field.

    AUTOBEGIN: ``set_config(..., is_local=true)`` runs before the yield, so the session is
    already inside a (transaction-local GUC) transaction. NEVER wrap the body in
    ``session.begin()`` — that double-begin error a broad ``except`` can swallow into a
    fail-OPEN control (banked rule 6; Sentinel ADR-0026). Read/write directly on the autobegun
    transaction; commit explicitly for writes. The GUC is ``SET LOCAL`` — it reverts at
    transaction end, so a pool-reused connection never leaks a stale tenant context, and an
    unset/empty GUC collapses the RLS NULLIF predicate to zero rows (fail-closed), never
    widening scope.
    """
    if not tenant_id or not tenant_id.strip():
        raise TenantContextRequiredError(
            "tenant_id must be a non-empty string sourced from the verified JWT claims. "
            "get_tenant_session refuses to open without a tenant context (fail-closed)."
        )
    factory = _get_app_session_factory()
    async with factory() as session:
        await session.execute(
            text("SELECT set_config(:guc, :tid, true)"),
            {"guc": TENANT_GUC, "tid": tenant_id},
        )
        yield session
