"""Database engines + session factories for the Delta ledger (D-003).

Mirrors the proven Sentinel F-003b two-role design
(``Anoryx-Sentinel/src/persistence/database.py``):

TWO ENGINES, TWO URLs (both required in .env):
  DATABASE_URL      — privileged owner role (BYPASSRLS). Migrations, admin /
                      break-glass maintenance. NEVER serves tenant request traffic.
  APP_DATABASE_URL  — delta_app role (LOGIN, NOSUPERUSER, NOBYPASSRLS, NOCREATEDB,
                      NOCREATEROLE). ALL tenant-scoped ledger traffic. Every checkout
                      sets the transaction-local GUC app.current_tenant_id before any
                      tenant query runs, and RLS is enforced regardless of application
                      correctness because the role cannot bypass it.

Neither URL nor any credential is ever logged or printed.
"""

from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from . import DELTA_APP_ROLE, TENANT_GUC  # noqa: F401  (re-export anchors / docs)


class TenantContextRequiredError(RuntimeError):
    """Raised by get_tenant_session() when tenant_id is missing/empty/whitespace.

    Fail-closed: no tenant session is opened without a valid tenant context. The
    caller must supply the tenant_id from an authenticated source, never from a
    client-supplied header.
    """


def _to_asyncpg_url(raw: str) -> str:
    """Convert a sync/psycopg postgres URL to asyncpg form. Never logged."""
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _privileged_database_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "DATABASE_URL is not set. This is the privileged (owner/BYPASSRLS) "
            "connection used for migrations and admin tooling. See Delta/.env.example."
        )
    return _to_asyncpg_url(raw)


def _app_database_url() -> str:
    raw = os.environ.get("APP_DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "APP_DATABASE_URL is not set. This is the delta_app (NOBYPASSRLS) "
            "connection used for all tenant-scoped ledger traffic. See "
            "Delta/.env.example."
        )
    return _to_asyncpg_url(raw)


# --- Privileged engine (owner / BYPASSRLS) — migrations, admin. Small pool. -------
_privileged_engine: object | None = None
_privileged_session_factory: async_sessionmaker | None = None


def _get_privileged_engine():  # type: ignore[return]
    global _privileged_engine
    if _privileged_engine is None:
        from sqlalchemy.ext.asyncio import create_async_engine as _cae

        _privileged_engine = _cae(
            _privileged_database_url(),
            pool_size=2,
            max_overflow=3,
            pool_pre_ping=True,
            echo=False,
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


# --- App engine (delta_app / NOBYPASSRLS) — tenant traffic. Standard pool. ---------
_app_engine: object | None = None
_app_session_factory: async_sessionmaker | None = None


def _get_app_engine():  # type: ignore[return]
    global _app_engine
    if _app_engine is None:
        from sqlalchemy.ext.asyncio import create_async_engine as _cae

        _app_engine = _cae(
            _app_database_url(),
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            echo=False,
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


def reset_engines() -> None:
    """Drop the cached engines/factories (test fixtures rebuild per event loop)."""
    global _privileged_engine, _privileged_session_factory, _app_engine, _app_session_factory
    _privileged_engine = None
    _privileged_session_factory = None
    _app_engine = None
    _app_session_factory = None


@asynccontextmanager
async def get_privileged_session() -> AsyncIterator[AsyncSession]:
    """Privileged session (DATABASE_URL / owner / BYPASSRLS).

    For migrations-adjacent admin tooling and break-glass maintenance only. Sets no
    tenant GUC; RLS is bypassed by the role. NEVER use for ordinary tenant traffic.
    """
    factory = _get_privileged_session_factory()
    async with factory() as session:
        yield session


@asynccontextmanager
async def get_tenant_session(tenant_id: str) -> AsyncIterator[AsyncSession]:
    """Tenant-scoped session (APP_DATABASE_URL / delta_app / NOBYPASSRLS).

    FAIL-CLOSED: raises TenantContextRequiredError before opening a transaction if
    tenant_id is missing/empty/whitespace.

    AUTOBEGINS: set_config runs before the yield, so the session is already in a
    transaction. NEVER wrap this in ``session.begin()`` — that raises the F-007
    double-begin error which a broad ``except`` can swallow into a fail-open control
    (Sentinel ADR-0026). Read directly on the autobegun transaction; for writes,
    commit explicitly.

    The GUC is transaction-local (is_local=true): it clears at commit/rollback, so a
    pool-reused connection never leaks a stale tenant context. A mid-transaction
    clear collapses the NULLIF predicate to zero rows (fail-closed), never widening.
    """
    if not tenant_id or not tenant_id.strip():
        raise TenantContextRequiredError(
            "tenant_id must be a non-empty string. get_tenant_session() refuses to "
            "open a session without a valid tenant context (fail-closed)."
        )

    factory = _get_app_session_factory()
    async with factory() as session:
        await session.execute(
            text("SELECT set_config(:guc, :tid, true)"),
            {"guc": TENANT_GUC, "tid": tenant_id},
        )
        yield session
