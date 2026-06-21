"""Admin test fixtures (F-012a, ADR-0014).

Self-provisioning DB readiness mirrors tests/compliance/conftest.py (the F-011 CI
lesson): in CI the test packages run in alphabetical order, so tests/admin/ runs
BEFORE tests/persistence/ — a fresh CI database would have neither the schema nor
a provisioned sentinel_app when the admin DB tests run. This package therefore
provisions itself, and is DB-GATED: with no DATABASE_URL/APP_DATABASE_URL (or
Postgres unreachable) it is a no-op so the pure-unit admin auth tests still run.

DB-backed admin tests require:
  - Live Postgres via DATABASE_URL + APP_DATABASE_URL
  - SENTINEL_PROVISION_APP_ROLE=1
Pure-unit auth tests (the STEP-2 fail-closed / forgery vectors) have no DB
dependency and run without Postgres.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import subprocess
import sys
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

# Anoryx-Sentinel/ root (tests/admin/conftest.py -> ../.. ).
_SENTINEL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _parse_pg(url: str):
    return re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)


# ---------------------------------------------------------------------------
# Tenant identifiers (admin tests act ACROSS tenants — A and B)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Admin app fixture (real gateway app + admin token) — shared by DB-backed
# admin endpoint tests. Skips when no DB is configured.
# ---------------------------------------------------------------------------

ADMIN_TOKEN = "admin-test-token-shared"  # noqa: S105 — test-only dummy, never a real secret
# F-014 STEP 7: the operator-session HMAC secret (distinct from ADMIN_TOKEN). A
# runtime-assembled test-only value — never a real secret (the F-005 lesson).
ADMIN_SESSION_SECRET = "session-test-secret-" + "x" * 24  # noqa: S105 — test-only dummy


@pytest.fixture()
def admin_app(monkeypatch):
    """Real gateway app with real DB env + SENTINEL_ADMIN_TOKEN set.

    list[str] settings are JSON-decoded from env; the root .env (loaded into
    os.environ above) carries non-JSON values, so pin valid JSON. DB urls +
    SENTINEL_KEY_SECRET come from the real env. Skips if no DB is configured.
    """
    if not os.environ.get("DATABASE_URL") or not os.environ.get("APP_DATABASE_URL"):
        pytest.skip("DATABASE_URL/APP_DATABASE_URL not set — skipping DB-backed admin test")

    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "[]")
    monkeypatch.setenv("ROUTER_DEFAULT_PROVIDERS", '["openai"]')
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", ADMIN_TOKEN)
    # F-014 STEP 7: provision the operator-session secret + reset its load-once
    # cache so the SSO callbacks can mint and require_admin can verify a session.
    monkeypatch.setenv("SENTINEL_ADMIN_SESSION_SECRET", ADMIN_SESSION_SECRET)
    from admin.sso import session as _op_session

    _op_session.reset_secret_cache_for_testing()
    if not os.environ.get("UPSTREAM_BASE_URL"):
        monkeypatch.setenv("UPSTREAM_BASE_URL", "https://upstream.example.invalid")
    if not os.environ.get("SENTINEL_KEY_SECRET"):
        monkeypatch.setenv("SENTINEL_KEY_SECRET", "test-key-secret")

    from gateway.config import _reset_settings
    from gateway.main import create_app

    _reset_settings()
    return create_app()


@pytest.fixture()
def admin_auth_headers() -> dict[str, str]:
    """Authorization headers carrying the shared test admin token (break-glass)."""
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture()
def operator_session_headers():
    """Factory: Authorization headers carrying a freshly-minted operator-session.

    Usage: operator_session_headers(tenant_id=..., role="tenant_admin",
    admin_user_id=...). The secret is provisioned by the admin_app fixture; this
    factory mints under the SAME secret so require_admin verifies it. The minted
    token is tenant-pinned to tenant_id (the R1 control under test).
    """
    from types import SimpleNamespace

    from admin.sso import session as _op_session

    def _make(
        *, tenant_id: str, role: str = "tenant_admin", admin_user_id: str | None = None
    ) -> dict[str, str]:
        # Mint under the same secret the admin_app fixture provisions. Set it here
        # too so the factory works even if requested before app construction.
        os.environ["SENTINEL_ADMIN_SESSION_SECRET"] = ADMIN_SESSION_SECRET
        _op_session.reset_secret_cache_for_testing()
        principal = SimpleNamespace(
            tenant_id=tenant_id,
            admin_user_id=admin_user_id or str(uuid.uuid4()),
            role=role,
        )
        token = _op_session.mint(principal)
        return {"Authorization": f"Bearer {token}"}

    return _make


@pytest.fixture()
def test_tenant_id() -> str:
    """A stable, unique tenant_id for tenant-A in admin tests (UUID v4)."""
    return str(uuid.uuid4())


@pytest.fixture()
def tenant_b_id() -> str:
    """A distinct tenant_id for tenant-B (cross-tenant isolation tests)."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# DB URL fixtures (skip cleanly when env vars absent)
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        pytest.skip("DATABASE_URL not set — skipping DB-backed admin test")
    return _to_asyncpg_url(raw)


@pytest.fixture()
def app_db_url() -> str:
    raw = os.environ.get("APP_DATABASE_URL", "")
    if not raw:
        pytest.skip("APP_DATABASE_URL not set — skipping DB-backed admin test")
    return _to_asyncpg_url(raw)


# ---------------------------------------------------------------------------
# Privileged session (DATABASE_URL / BYPASSRLS) — seed rows + global registry
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
# TRUNCATE teardown (cross-tenant committed-row proofs ONLY — vectors 8/10/14)
# events_audit_log has a BEFORE DELETE trigger (append-only); TRUNCATE bypasses
# it. Scoped (NOT autouse) so single-tenant no-commit tests never receive it.
# Local dev/CI Postgres only.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def truncate_audit_log_after() -> AsyncIterator[None]:
    """Yield, then TRUNCATE events_audit_log in teardown (privileged connection)."""
    yield
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        return
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
    """Dispose + null persistence.database engine caches after each test so the
    next test rebuilds engines in its own event loop (pytest-asyncio per-fn loop).
    No-op for pure-unit tests (caches stay None).
    """
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


# ---------------------------------------------------------------------------
# DB readiness (schema-at-head + sentinel_app provisioning) — DB-gated, autouse
# Mirrors tests/compliance/conftest.py::_ensure_compliance_db_ready exactly.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _ensure_admin_db_ready() -> AsyncIterator[None]:
    db_url = os.environ.get("DATABASE_URL", "")
    app_url = os.environ.get("APP_DATABASE_URL", "")
    if not db_url or not app_url:
        yield  # no DB configured -> pure-unit tests only
        return

    m = _parse_pg(db_url)
    if not m:
        yield
        return

    import asyncpg

    # Reachability probe — if Postgres is down, no-op so pure-unit tests run.
    try:
        probe = await asyncpg.connect(
            user=m.group(1),
            password=m.group(2),
            host=m.group(3),
            port=int(m.group(4)),
            database=m.group(5),
            timeout=3,
        )
        await probe.close()
    except Exception:
        yield
        return

    # 1) Schema at head (creates events_audit_log + sentinel_app role).
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(_SENTINEL_ROOT, "src")
    from dotenv import dotenv_values

    env.update({k: v for k, v in dotenv_values(_ENV_PATH).items() if v is not None})
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=_SENTINEL_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(f"_ensure_admin_db_ready: alembic upgrade head failed:\n{result.stderr}")

    # 2) Provision sentinel_app's password (SCRAM verifier; plaintext never in SQL).
    app_pw_m = re.match(r"postgresql(?:\+asyncpg)?://[^:]+:([^@]+)@", app_url)
    if app_pw_m:
        app_password = app_pw_m.group(1)
        conn = await asyncpg.connect(
            user=m.group(1),
            password=m.group(2),
            host=m.group(3),
            port=int(m.group(4)),
            database=m.group(5),
        )
        try:
            salt = os.urandom(16)
            iters = 4096
            salted = hashlib.pbkdf2_hmac("sha256", app_password.encode("utf-8"), salt, iters)
            client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
            stored_key = hashlib.sha256(client_key).digest()
            server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
            verifier = (
                f"SCRAM-SHA-256${iters}"
                f":{base64.b64encode(salt).decode()}"
                f"${base64.b64encode(stored_key).decode()}"
                f":{base64.b64encode(server_key).decode()}"
            )
            await conn.execute(f"ALTER ROLE sentinel_app WITH PASSWORD '{verifier}'")
        finally:
            await conn.close()

    yield
