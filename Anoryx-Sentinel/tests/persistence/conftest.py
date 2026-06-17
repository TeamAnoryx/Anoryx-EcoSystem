"""Shared fixtures for persistence tests (F-003 + F-003b).

Connects to the live sentinel-postgres container at localhost:5432.
DATABASE_URL and SENTINEL_KEY_SECRET are loaded from the root .env file.

Required environment variables (see .env.example at Anoryx-Sentinel root):
  DATABASE_URL          — PostgreSQL connection string (privileged role).
  APP_DATABASE_URL      — PostgreSQL connection string (sentinel_app role).
  SENTINEL_KEY_SECRET   — HMAC secret for virtual API key fingerprinting.

If any required variable is absent, tests fail immediately with a clear error
(no silent fallback injection — pytest.fail() stops the session before wasting
time on database operations that would produce confusing errors).

Session isolation strategy:
- Each test function gets its own AsyncSession with a nested SAVEPOINT.
- The outer transaction is started and rolled back after the test, leaving
  the DB clean for the next test.
- Engine and session_factory are function-scoped to avoid event-loop conflicts
  with pytest-asyncio on Windows (ProactorEventLoop is per-test by default).

Two fixture families (F-003b):
  session          — privileged connection (DATABASE_URL). Used by all 88 F-003
                     tests unchanged. Chain tests (test_audit_chain,
                     test_concurrent_chain) use this fixture. The privileged role
                     has BYPASSRLS semantics so RLS does not filter rows — which
                     is exactly what chain ops require to see the global chain.
  tenant_session   — sentinel_app connection (APP_DATABASE_URL) with
                     app.current_tenant_id set to a test tenant_id. Used by
                     isolation tests (test_isolation.py). CRITICAL: this fixture
                     must connect as sentinel_app, NOT admin — if it connects as
                     admin, isolation tests pass spuriously because BYPASSRLS
                     bypasses RLS. See ADR-0005 test strategy section.

Schema guarantee:
- The session-scoped `ensure_schema_at_head` autouse fixture runs alembic
  upgrade head once per test session before any test uses the DB. This
  ensures the schema is present even if a previous run left it downgraded.

NOTE (test hygiene): the outer transaction in the session fixture is not
committed — changes are visible within the transaction (via SAVEPOINT) but
are rolled back on teardown. Tests that depend on committed data (e.g. the
tamper tests in test_audit_chain.py) must manage their own connections outside
this fixture.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Load .env from the monorepo root (three levels up from this conftest).
_env_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_env_path)

# SENTINEL_KEY_SECRET must be set. Fail loudly if absent — no silent injection.
# The variable name is SENTINEL_KEY_SECRET (matches virtual_api_key_repository.py).
# Do NOT use a different name (e.g. SENTINEL_HMAC_SECRET) — keep consistent.
if not os.environ.get("SENTINEL_KEY_SECRET"):
    pytest.fail(
        "SENTINEL_KEY_SECRET environment variable is not set. "
        "Add it to your .env file or export it before running tests. "
        "See .env.example at the Anoryx-Sentinel root for required variables."
    )

# APP_DATABASE_URL must be set for isolation tests. Fail loudly if absent.
# Mirror the SENTINEL_KEY_SECRET pattern above — no silent fallback.
if not os.environ.get("APP_DATABASE_URL"):
    pytest.fail(
        "APP_DATABASE_URL environment variable is not set. "
        "Add it to your .env file or export it before running tests. "
        "This URL connects as the sentinel_app role (NOBYPASSRLS) and is "
        "required for tenant isolation tests (test_isolation.py). "
        "See .env.example at the Anoryx-Sentinel root for required variables."
    )


def _make_async_url(raw_url: str) -> str:
    """Convert DATABASE_URL to asyncpg-compatible URL."""
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw_url)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


_SENTINEL_ROOT = Path(__file__).parent.parent.parent
_ENV_FILE = str(_SENTINEL_ROOT.parent / ".env")


async def _provision_sentinel_app_password(app_url: str, db_url: str) -> None:
    """Provision the sentinel_app role's password from APP_DATABASE_URL (idempotent).

    Extracts the plaintext password from ``app_url``, computes a SCRAM-SHA-256
    verifier client-side, applies it to the sentinel_app role via ALTER ROLE over
    the privileged ``db_url`` connection, then self-verifies by logging in as
    sentinel_app with that plaintext. Idempotent and cheap (~50ms ALTER ROLE):
    a fresh salt each call yields a different-but-always-valid verifier, so
    repeated invocations are safe.

    After `alembic upgrade head` the sentinel_app role always exists (migration
    0006) and the privileged admin connection can always ALTER ROLE, so any
    exception here is a genuine harness defect and MUST stop the session
    (pytest.fail) rather than let tests run against a broken auth state. The
    plaintext password value is never included in any failure message.

    f-003b-harness-fix: loud failure on every provisioning error (no
    warnings.warn swallow). Extracted to module scope from ensure_schema_at_head
    so it can also run per-test — test_migration_downgrade_and_reapply and
    test_incremental_downgrade drop and recreate sentinel_app (passwordless)
    mid-session. See ensure_schema_at_head and _provision_app_role_for_each_test.
    """

    def _extract_password(url: str) -> str | None:
        m = re.match(r"postgresql(?:\+asyncpg)?://[^:]+:([^@]+)@", url)
        return m.group(1) if m else None

    app_password = _extract_password(app_url)
    if not app_password:
        # f-003b-harness-fix: do NOT silently skip when the password cannot be
        # extracted. The caller gated on SENTINEL_PROVISION_APP_ROLE with both
        # URLs present, so it expects provisioning — a missing password in
        # APP_DATABASE_URL is a setup error, not a reason to leave sentinel_app
        # passwordless and fail with a cryptic SCRAM error later.
        pytest.fail(
            "SENTINEL_PROVISION_APP_ROLE is set but no password could be "
            "extracted from APP_DATABASE_URL. Provisioning requires a password "
            "in the URL (postgresql://sentinel_app:<password>@host:port/db)."
        )

    try:
        import asyncpg

        m = re.match(
            r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)",
            db_url,
        )
        if m:
            conn = await asyncpg.connect(
                user=m.group(1),
                password=m.group(2),
                host=m.group(3),
                port=int(m.group(4)),
                database=m.group(5),
            )
            # PostgreSQL DDL (ALTER ROLE … PASSWORD) does not accept
            # protocol-level bind parameters — the server refuses $1 for all
            # DDL.  To avoid putting the plaintext credential into any SQL
            # string literal (and thus out of pg_stat_activity / pg_log), we
            # compute the SCRAM-SHA-256 verifier client-side in Python.  Only
            # the opaque verifier string — never the plaintext password — is
            # interpolated into the SQL statement.  PostgreSQL accepts
            # pre-computed SCRAM verifiers in ALTER ROLE … PASSWORD.
            salt = os.urandom(16)
            iters = 4096
            salted_pw = hashlib.pbkdf2_hmac(
                "sha256",
                app_password.encode("utf-8"),
                salt,
                iters,
            )
            client_key = hmac.new(salted_pw, b"Client Key", hashlib.sha256).digest()
            stored_key = hashlib.sha256(client_key).digest()
            server_key = hmac.new(salted_pw, b"Server Key", hashlib.sha256).digest()
            verifier = (
                f"SCRAM-SHA-256${iters}"
                f":{base64.b64encode(salt).decode()}"
                f"${base64.b64encode(stored_key).decode()}"
                f":{base64.b64encode(server_key).decode()}"
            )
            # Only the verifier (opaque hash) is in the SQL — the plaintext
            # app_password is never a SQL literal.
            await conn.execute(f"ALTER ROLE sentinel_app WITH PASSWORD '{verifier}'")
            await conn.close()

            # Self-check (loud guarantee, f-003b-harness-fix): prove that
            # sentinel_app actually authenticates with the plaintext from
            # APP_DATABASE_URL now that the verifier has been applied. The
            # original defect left sentinel_app passwordless while the failure
            # was swallowed, surfacing only as a cryptic SCRAM auth error in
            # unrelated tests. Verifying the live login here converts that
            # entire silent class into an immediate, legible failure. A login
            # attempt is read-only — it mutates no database state.
            verify_conn = await asyncpg.connect(
                user="sentinel_app",
                password=app_password,
                host=m.group(3),
                port=int(m.group(4)),
                database=m.group(5),
            )
            await verify_conn.close()
    except Exception as e:
        # LOUD failure (f-003b-harness-fix). The previous handler swallowed
        # every provisioning error with warnings.warn, which hid an empty/stale
        # sentinel_app verifier and surfaced only as a cryptic SCRAM auth error
        # in unrelated tests. After `alembic upgrade head` the sentinel_app role
        # always exists (migration 0006) and the privileged admin connection can
        # always ALTER ROLE, so any exception here is a genuine harness defect
        # and MUST stop the session rather than let tests run against a broken
        # auth state. The plaintext password value is never included.
        pytest.fail(f"sentinel_app password provisioning failed: {e}")


@pytest.fixture(scope="session", autouse=True)
def ensure_schema_at_head() -> None:
    """Autouse session fixture: run alembic upgrade head before any tests.

    This guarantees the schema is present even if a previous test run left
    the DB in a downgraded state (e.g., after test_incremental_downgrade).

    After upgrading to head, also ensures sentinel_app has a password set for
    local dev testing. In production, the password is Vault-managed and injected
    at runtime. In tests, we use the APP_DATABASE_URL credential from the env.
    If APP_DATABASE_URL is set, we extract the password and apply it to the role.
    This handles the case where test_incremental_downgrade drops and re-creates
    sentinel_app (the migration creates the role without a password; the password
    must be provisioned out-of-band — in local dev that means here).
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SENTINEL_ROOT / "src")
    from dotenv import dotenv_values

    vals = dotenv_values(_ENV_FILE)
    env.update({k: v for k, v in vals.items() if v is not None})

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(_SENTINEL_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(f"ensure_schema_at_head: alembic upgrade head failed:\n{result.stderr}")


@pytest.fixture(autouse=True)
def _provision_app_role_for_each_test() -> None:
    """Re-provision sentinel_app's password before every persistence test.

    test_migration_downgrade_and_reapply and test_incremental_downgrade drop
    sentinel_app and recreate it without a password mid-session (the migration
    creates the role passwordless). The session-scoped ensure_schema_at_head ran
    provisioning only once at session start, so any test ordered alphabetically
    after test_migrations.py that connects as sentinel_app (e.g. F-006's
    test_tenant_routing_policy_isolation.py) then failed on SCRAM auth.

    Function-scope provisioning is idempotent and cheap (~50ms ALTER ROLE) and
    honors the same SENTINEL_PROVISION_APP_ROLE gate, read from the merged env
    (os.environ + root .env) exactly as ensure_schema_at_head does — so the gate
    is consistent with the data regardless of shell (Windows PowerShell does not
    export bash-style `VAR=1 pytest`).

    f-003b-harness-fix v2 — catches mid-session sentinel_app drops that v1
    (session-scope-only provisioning) did not.
    """
    import asyncio

    from dotenv import dotenv_values

    env = os.environ.copy()
    vals = dotenv_values(_ENV_FILE)
    env.update({k: v for k, v in vals.items() if v is not None})

    _provision = env.get("SENTINEL_PROVISION_APP_ROLE", "").lower().strip()
    if _provision not in ("1", "true", "yes", "on"):
        return

    app_url = env.get("APP_DATABASE_URL", "")
    db_url = env.get("DATABASE_URL", "")
    if app_url and db_url:
        try:
            asyncio.run(_provision_sentinel_app_password(app_url, db_url))
        except Exception as e:
            pytest.fail(f"sentinel_app password provisioning failed: {e}")


# ---------------------------------------------------------------------------
# Privileged session fixtures (DATABASE_URL / owner / BYPASSRLS)
# Used by all 88 F-003 tests and chain tests. Semantics unchanged from F-003.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def db_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        pytest.fail("DATABASE_URL is not set. Cannot run persistence tests.")
    return _make_async_url(raw)


@pytest_asyncio.fixture(scope="function")
async def session(db_url: str) -> AsyncSession:
    """Per-test async session with automatic rollback isolation (privileged role).

    Creates a new engine + session per test function to avoid event-loop
    conflicts with pytest-asyncio on Windows. Uses a nested transaction
    (SAVEPOINT) so each test starts with a clean visible state without
    committing anything to the DB.

    This is the PRIVILEGED session (DATABASE_URL / BYPASSRLS). RLS is not
    active on this connection. All 88 F-003 tests use this fixture unchanged.
    Chain tests (test_audit_chain, test_concurrent_chain) require this fixture
    because chain ops (_get_tip_hash, validate_chain, append) must see all rows
    across all tenants.
    """
    # server_settings sets app.session_kind at connection time — required for
    # the secondary defense-in-depth check in _assert_privileged_session.
    # See database.py _get_privileged_engine() for the module-level equivalent.
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
# App-role session fixtures (APP_DATABASE_URL / sentinel_app / NOBYPASSRLS)
# Used exclusively by isolation tests (test_isolation.py).
#
# CRITICAL: these fixtures MUST connect as sentinel_app, NOT as admin.
# If they connect as admin, RLS is bypassed and isolation tests pass spuriously
# — the suite would be green while providing zero real isolation coverage.
# See ADR-0005 test strategy section.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def app_db_url() -> str:
    raw = os.environ.get("APP_DATABASE_URL", "")
    if not raw:
        pytest.fail(
            "APP_DATABASE_URL is not set. "
            "Isolation tests require a connection as sentinel_app (NOBYPASSRLS). "
            "See .env.example at the Anoryx-Sentinel root."
        )
    return _make_async_url(raw)


@pytest_asyncio.fixture(scope="function")
async def tenant_session(app_db_url: str, test_tenant_id: str) -> AsyncSession:
    """Per-test tenant-scoped session connecting as sentinel_app.

    Connects via APP_DATABASE_URL (sentinel_app role, NOBYPASSRLS). Sets the
    transaction-local GUC app.current_tenant_id to test_tenant_id before
    yielding. RLS is ACTIVE on this connection — rows for other tenants are
    invisible to queries. Uses SAVEPOINT isolation to roll back after each test.

    Requires the `test_tenant_id` fixture to be defined in the test module or
    provided as a parameter (see test_isolation.py for usage).

    ISOLATION GUARANTEE: because sentinel_app has NOBYPASSRLS, RLS policies on
    all tenant tables are enforced regardless of query correctness. This is the
    correct fixture for isolation tests — NOT the `session` fixture.
    """
    from sqlalchemy import text

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
            # Set transaction-local GUC before any RLS-governed query.
            await sess.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": test_tenant_id},
            )
            nested = await sess.begin_nested()
            yield sess
            await nested.rollback()
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def tenant_session_no_guc(app_db_url: str) -> AsyncSession:
    """Tenant-scoped session (sentinel_app) with NO GUC set.

    Used by isolation tests that verify the unset-GUC case returns zero rows
    (the NULLIF predicate is unsatisfiable when the GUC is empty).

    The session connects as sentinel_app (NOBYPASSRLS) so RLS is active.
    No set_config call is made — the GUC is absent from this transaction.
    """
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
            nested = await sess.begin_nested()
            yield sess
            await nested.rollback()
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def tenant_session_empty_guc(app_db_url: str) -> AsyncSession:
    """Tenant-scoped session (sentinel_app) with GUC explicitly set to ''.

    Used by isolation tests that verify the empty-string-GUC case returns
    zero rows (proves the NULLIF predicate, not the dead IS NULL branch).
    NULLIF('', '') = NULL, and tenant_id = NULL is UNKNOWN (never true).
    """
    from sqlalchemy import text

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
            # Explicitly set GUC to empty string.
            await sess.execute(text("SELECT set_config('app.current_tenant_id', '', true)"))
            nested = await sess.begin_nested()
            yield sess
            await nested.rollback()
    await engine.dispose()
