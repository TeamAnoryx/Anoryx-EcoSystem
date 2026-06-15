"""Database engine and session factories for Anoryx-Sentinel (F-003b).

F-003b implements Option α from ADR-0005: two physically separate engines,
each bound to a distinct Postgres role.

TWO ENGINES, TWO URLs (BOTH must be present in .env):
  DATABASE_URL       — privileged role (owner / BYPASSRLS).
                       Used for: hash-chain ops (append, _get_tip_hash,
                       validate_chain), Alembic migrations, admin tooling.
                       Never used to serve ordinary tenant request traffic.
  APP_DATABASE_URL   — sentinel_app role (LOGIN, NOSUPERUSER, NOBYPASSRLS,
                       NOCREATEDB, NOCREATEROLE).
                       Used for: all tenant-scoped request traffic.
                       Every checkout sets the transaction-local GUC
                       app.current_tenant_id before any tenant query runs.

Both URLs must be present in .env (see .env.example for placeholder values).
Neither URL nor any credential is ever logged or printed.

BACK-COMPAT NOTE:
  get_async_session() is kept as a deprecated alias for get_privileged_session().
  The 88 F-003 tests used the admin connection and all their assertions remain
  valid on the privileged engine (which bypasses RLS, matching the original
  behaviour). Chain tests (test_audit_chain, test_concurrent_chain) must run
  on the privileged session — they already do via get_async_session(), which
  now routes to the privileged engine.
  New code MUST NOT use get_async_session() — use the explicit factories instead.
"""

from __future__ import annotations

import os
import re
import warnings
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
)

# ---------------------------------------------------------------------------
# Role constants — single source of truth used by _assert_privileged_session.
# Changing the sentinel_app role name in Postgres requires updating this value.
# ---------------------------------------------------------------------------

#: The non-privileged application login role (NOBYPASSRLS).
#: Any session connecting as this role MUST NOT be used for chain operations.
SENTINEL_APP_ROLE: str = "sentinel_app"

# ---------------------------------------------------------------------------
# Custom exception types (also importable from persistence.errors)
# ---------------------------------------------------------------------------


class TenantContextRequiredError(RuntimeError):
    """Raised by get_tenant_session() when tenant_id is missing, empty, or whitespace.

    This is a hard fail-closed guard: no tenant session is opened without a
    valid tenant context. The caller must supply the tenant_id sourced from the
    authenticated virtual_api_keys row — never from a client-supplied header.
    """


class PrivilegedSessionRequiredError(RuntimeError):
    """Raised when a chain operation is invoked on a non-privileged session.

    Chain ops (append, _get_tip_hash, validate_chain) read and write the global
    cross-tenant chain. Running them on a tenant-scoped session would truncate
    the visible rows to one tenant's subset, forking or fragmenting the chain.
    These methods assert they are running on the privileged session and raise
    this error if they detect otherwise.
    """


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def _to_asyncpg_url(raw: str) -> str:
    """Convert a sync/psycopg postgres URL to asyncpg-compatible form.

    Converts postgresql:// and postgresql+psycopg:// to postgresql+asyncpg://.
    Does NOT log or return the URL to callers beyond what is strictly needed.
    """
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _privileged_database_url() -> str:
    """Return the asyncpg-compatible DATABASE_URL (privileged role).

    Raises RuntimeError if DATABASE_URL is absent.
    The URL is never logged.
    """
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Add it to .env (see .env.example). "
            "This URL is the privileged (owner/BYPASSRLS) connection used for "
            "migrations, chain ops, and admin tooling."
        )
    return _to_asyncpg_url(raw)


def _app_database_url() -> str:
    """Return the asyncpg-compatible APP_DATABASE_URL (sentinel_app role).

    Raises RuntimeError if APP_DATABASE_URL is absent.
    The URL is never logged.
    """
    raw = os.environ.get("APP_DATABASE_URL", "")
    if not raw:
        raise RuntimeError(
            "APP_DATABASE_URL environment variable is not set. "
            "Add it to .env (see .env.example). "
            "This URL is the sentinel_app (NOBYPASSRLS) connection used for "
            "all tenant-scoped request traffic."
        )
    return _to_asyncpg_url(raw)


# ---------------------------------------------------------------------------
# Privileged engine (DATABASE_URL / owner / BYPASSRLS)
# Lazy module-level singleton — small pool; chain ops are serialized by an
# advisory lock and admin use is infrequent.
# ---------------------------------------------------------------------------

_privileged_engine: object | None = None
_privileged_session_factory: async_sessionmaker | None = None


def _get_privileged_engine():  # type: ignore[return]
    global _privileged_engine
    if _privileged_engine is None:
        from sqlalchemy.ext.asyncio import create_async_engine as _cae

        url = _privileged_database_url()
        # Small pool: chain ops are advisory-lock-serialized; admin use is rare.
        #
        # Defense-in-depth marker: app.session_kind is set to 'privileged' via
        # asyncpg's server_settings connect argument.  asyncpg passes these as
        # startup parameters before the first query, making them visible as GUCs
        # on the server side for the lifetime of that physical connection.
        # This marker is SECONDARY corroboration only — the primary check in
        # _assert_privileged_session is `SELECT current_user` (the Postgres role),
        # which a sentinel_app session cannot fake regardless of SET statements.
        # Postgres allows any role to SET a custom GUC in its own session, so
        # the marker ALONE is insufficient; the role check is the load-bearing
        # guard.  Setting it at connect time via server_settings means neither the
        # application nor pool checkout code needs to emit an extra SQL statement —
        # it is set before the first query on each physical connection.
        _privileged_engine = _cae(
            url,
            pool_size=2,
            max_overflow=3,
            pool_pre_ping=True,
            echo=False,
            connect_args={"server_settings": {"app.session_kind": "privileged"}},
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


# ---------------------------------------------------------------------------
# App engine (APP_DATABASE_URL / sentinel_app / NOBYPASSRLS)
# Lazy module-level singleton — standard pool for tenant traffic.
# ---------------------------------------------------------------------------

_app_engine: object | None = None
_app_session_factory: async_sessionmaker | None = None


def _get_app_engine():  # type: ignore[return]
    global _app_engine
    if _app_engine is None:
        from sqlalchemy.ext.asyncio import create_async_engine as _cae

        url = _app_database_url()
        _app_engine = _cae(
            url,
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


# ---------------------------------------------------------------------------
# Public session context managers
# ---------------------------------------------------------------------------


@asynccontextmanager
async def get_privileged_session() -> AsyncIterator[AsyncSession]:
    """Privileged session context manager (DATABASE_URL / owner / BYPASSRLS).

    WHEN TO USE: hash-chain ops (append, _get_tip_hash, validate_chain),
    Alembic migrations (via alembic.ini, not here), and admin/break-glass
    maintenance. NEVER use for ordinary tenant request traffic.

    This session does NOT set any tenant GUC. RLS is bypassed because the
    underlying role has BYPASSRLS semantics. Queries see all rows across all
    tenants — which is exactly what chain ops require to maintain the global
    single chain.

    Usage:
        async with get_privileged_session() as session:
            async with session.begin():
                repo = AuditLogRepository(session)
                result = await repo.validate_chain()
    """
    factory = _get_privileged_session_factory()
    async with factory() as session:
        yield session


@asynccontextmanager
async def get_tenant_session(tenant_id: str) -> AsyncIterator[AsyncSession]:
    """Tenant-scoped session context manager (APP_DATABASE_URL / sentinel_app).

    WHEN TO USE: all tenant request traffic — team reads, project reads, policy
    reads, virtual API key lookups, user reads, audit-log tenant viewing.

    FAIL-CLOSED: raises TenantContextRequiredError BEFORE opening a transaction
    if tenant_id is missing, empty, or whitespace. The GUC is set only after
    this guard passes. The application must supply the tenant_id sourced from
    the authenticated virtual_api_keys row — never from a client-supplied header.

    GUC LIFETIME (MED-1 / ADR-0005 §GUC-lifetime):
        The GUC is set via set_config(..., is_local=true), which makes it
        TRANSACTION-LOCAL: it is automatically cleared when the transaction ends
        (commit or rollback), preventing stale context from leaking across
        pool-reused connections.  A mid-transaction RESET by attacker-controlled
        SQL is not exploitable because:
          (a) The privilege gate in _assert_privileged_session is ROLE-based, not
              GUC-based — even if the GUC is cleared mid-tx, chain ops remain
              blocked because sentinel_app != the privileged role.
          (b) RLS USING predicates evaluate NULLIF(current_setting(...), ''),
              which collapses '' to NULL and returns zero rows, so a mid-tx clear
              produces fail-closed zero-row results, never cross-tenant access.
        The GUC is therefore pinned for the transaction lifetime; a mid-tx clear
        silently narrows scope to zero rows rather than widening it.

    RLS on all tenant tables filters rows to this tenant_id only. The
    sentinel_app role is NOBYPASSRLS so RLS cannot be bypassed by the
    application — it is enforced regardless of application correctness.

    Usage:
        async with get_tenant_session(tenant_id) as session:
            async with session.begin():
                repo = TeamRepository(session)
                team = await repo.get_by_id(team_id, caller_tenant_id=tenant_id)
    """
    if not tenant_id or not tenant_id.strip():
        raise TenantContextRequiredError(
            "tenant_id must be a non-empty string. "
            "Obtain the tenant_id from the authenticated virtual_api_keys row — "
            "never from a client-supplied header. "
            "get_tenant_session() refuses to open a session without a valid "
            "tenant context (fail-closed)."
        )

    factory = _get_app_session_factory()
    async with factory() as session:
        # Set transaction-local GUC (is_local=True) before any tenant query.
        # is_local=True is equivalent to SET LOCAL — the GUC reverts to its
        # prior value at the end of the current transaction.  This prevents
        # stale context from leaking across pool-reused connections.
        # See GUC LIFETIME note in the docstring above for security analysis.
        await session.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": tenant_id},
        )
        yield session


@asynccontextmanager
async def get_async_session() -> AsyncIterator[AsyncSession]:
    """DEPRECATED: use get_privileged_session() or get_tenant_session() instead.

    Kept for back-compat with the 88 F-003 tests which used this name.
    Routes to get_privileged_session() — semantics are unchanged for those tests
    (admin connection, no GUC, BYPASSRLS). All F-003 assertions remain valid.

    New code MUST NOT call get_async_session(). Use the explicit factories:
      - Chain ops / admin:  get_privileged_session()
      - Tenant traffic:     get_tenant_session(tenant_id)
    """
    warnings.warn(
        "get_async_session() is deprecated. "
        "Use get_privileged_session() for chain/admin ops or "
        "get_tenant_session(tenant_id) for tenant traffic.",
        DeprecationWarning,
        stacklevel=2,
    )
    async with get_privileged_session() as session:
        yield session


def create_engine_from_env() -> object:
    """Create and return a SQLAlchemy async engine from DATABASE_URL.

    Exposed for use by test fixtures that build their own engine.
    Returns the privileged engine (DATABASE_URL) with the session_kind marker
    set via server_settings so _assert_privileged_session's secondary check passes.
    """
    from sqlalchemy.ext.asyncio import create_async_engine as _cae

    url = _privileged_database_url()
    return _cae(
        url,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
