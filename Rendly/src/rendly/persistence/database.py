"""Database engines + session factories for Rendly identity persistence (R-004).

SYNC analog (Fork D) of Delta D-003's async ``database.py`` — Rendly is sync to match
R-003's sync ``UserStore`` / ``RefreshTokenStore`` seams. Uses sync SQLAlchemy
``Session`` over the **psycopg** driver (NOT asyncpg).

TWO ENGINES, TWO URLs (both required in the environment):
  DATABASE_URL      — privileged owner role (BYPASSRLS). Migrations, admin, and the
                      cross-tenant login credential lookup (the username is global; the
                      tenant is unknown until the row is read). NEVER serves ordinary
                      tenant traffic.
  APP_DATABASE_URL  — ``rendly_app`` role (LOGIN, NOSUPERUSER, NOBYPASSRLS). ALL
                      tenant-scoped traffic. Every checkout sets the transaction-local
                      GUC ``app.current_tenant_id`` before any tenant query runs, and
                      RLS is enforced regardless of application correctness because the
                      role cannot bypass it.

Neither URL nor any credential is ever logged or printed.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from . import RENDLY_APP_ROLE, TENANT_GUC  # noqa: F401  (re-export anchors / docs)


class TenantContextRequiredError(RuntimeError):
    """Raised by :func:`get_tenant_session` when ``tenant_id`` is missing/empty/whitespace.

    Fail-closed: no tenant session is opened without a valid tenant context. The caller
    must supply ``tenant_id`` from an authenticated source (the stored ``User`` / the
    refresh record), never from a client-supplied header.
    """


def _to_psycopg_url(raw: str) -> str:
    """Rewrite a postgres URL to the sync psycopg driver form. Never logged.

    ``postgresql://`` and ``postgresql+asyncpg://`` both become
    ``postgresql+psycopg://`` so the same connection string works whether it was written
    for the bare driver or the (Delta) asyncpg form.
    """
    url = re.sub(r"^postgresql\+asyncpg://", "postgresql+psycopg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+psycopg://", url)
    return url


def _privileged_database_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "DATABASE_URL is not set. This is the privileged (owner/BYPASSRLS) connection "
            "used for migrations, admin tooling, and the cross-tenant login lookup. See "
            "Rendly/docker-compose.yml for the matching connection string."
        )
    return _to_psycopg_url(raw)


def _app_database_url() -> str:
    raw = os.environ.get("APP_DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "APP_DATABASE_URL is not set. This is the rendly_app (NOBYPASSRLS) connection "
            "used for all tenant-scoped traffic. See Rendly/docker-compose.yml."
        )
    return _to_psycopg_url(raw)


# --- Privileged engine (owner / BYPASSRLS) — migrations, admin, login lookup. ---------
_privileged_engine: Engine | None = None
_privileged_session_factory: sessionmaker | None = None


def _get_privileged_engine() -> Engine:
    global _privileged_engine
    if _privileged_engine is None:
        _privileged_engine = create_engine(
            _privileged_database_url(),
            pool_size=2,
            max_overflow=3,
            pool_pre_ping=True,
            echo=False,
            # Pin the session time zone to UTC so timestamptz round-trips return aware-UTC
            # datetimes regardless of the server's local tz (the wire format is RFC 3339 UTC).
            connect_args={"options": "-c timezone=utc"},
        )
    return _privileged_engine


def _get_privileged_session_factory() -> sessionmaker:
    global _privileged_session_factory
    if _privileged_session_factory is None:
        _privileged_session_factory = sessionmaker(
            bind=_get_privileged_engine(),
            expire_on_commit=False,
            autoflush=False,
            autobegin=True,
        )
    return _privileged_session_factory


# --- App engine (rendly_app / NOBYPASSRLS) — tenant traffic. Standard pool. ------------
_app_engine: Engine | None = None
_app_session_factory: sessionmaker | None = None


def _get_app_engine() -> Engine:
    global _app_engine
    if _app_engine is None:
        _app_engine = create_engine(
            _app_database_url(),
            pool_size=5,
            max_overflow=10,
            pool_pre_ping=True,
            echo=False,
            # Pin the session time zone to UTC (see the privileged engine note).
            connect_args={"options": "-c timezone=utc"},
        )
    return _app_engine


def _get_app_session_factory() -> sessionmaker:
    global _app_session_factory
    if _app_session_factory is None:
        _app_session_factory = sessionmaker(
            bind=_get_app_engine(),
            expire_on_commit=False,
            autoflush=False,
            autobegin=True,
        )
    return _app_session_factory


def reset_engines() -> None:
    """Dispose + null both cached engines/factories.

    The test conftest calls this at SETUP (not only teardown) so a stale DSN from an
    earlier test module can never pollute a later one (banked rule 7).
    """
    global _privileged_engine, _privileged_session_factory, _app_engine, _app_session_factory
    if _privileged_engine is not None:
        _privileged_engine.dispose()
    if _app_engine is not None:
        _app_engine.dispose()
    _privileged_engine = None
    _privileged_session_factory = None
    _app_engine = None
    _app_session_factory = None


@contextmanager
def get_privileged_session() -> Iterator[Session]:
    """Privileged session (DATABASE_URL / owner / BYPASSRLS).

    For migrations-adjacent admin tooling, tenant provisioning, the cross-tenant login
    credential lookup, and discovering a refresh token's tenant by its hash. Sets NO
    tenant GUC; RLS is bypassed by the role. NEVER use for ordinary tenant traffic.

    For writes, the caller must call ``session.commit()``; uncommitted changes are rolled
    back by ``session.close()``.
    """
    factory = _get_privileged_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()


@contextmanager
def get_tenant_session(tenant_id: str) -> Iterator[Session]:
    """Tenant-scoped session (APP_DATABASE_URL / rendly_app / NOBYPASSRLS).

    FAIL-CLOSED: raises :class:`TenantContextRequiredError` BEFORE opening anything if
    ``tenant_id`` is missing/empty/whitespace.

    AUTOBEGINS: ``set_config`` runs before the yield, so the session is already inside a
    transaction when control returns. NEVER wrap this in ``session.begin()`` — a sync
    Session autobegins on first execute; an explicit ``begin()`` raises the double-begin
    error which a broad ``except`` can swallow into a fail-OPEN control (banked rule 6;
    Sentinel ADR-0026). Read directly on the autobegun transaction; for writes, call
    ``session.commit()`` explicitly.

    The GUC is transaction-local (``set_config(..., is_local=true)``): it clears at
    commit/rollback, so a pool-reused connection never leaks a stale tenant context, and
    a mid-transaction clear collapses the NULLIF predicate to zero rows (fail-closed),
    never widening. The ``set_config`` and every subsequent statement therefore share ONE
    transaction so the txn-local GUC stays in scope for the queries it guards.
    """
    if not tenant_id or not tenant_id.strip():
        raise TenantContextRequiredError(
            "tenant_id must be a non-empty string. get_tenant_session() refuses to open a "
            "session without a valid tenant context (fail-closed)."
        )
    factory = _get_app_session_factory()
    session = factory()
    try:
        session.execute(
            text("SELECT set_config(:guc, :tid, true)"),
            {"guc": TENANT_GUC, "tid": tenant_id},
        )
        yield session
    finally:
        session.close()
