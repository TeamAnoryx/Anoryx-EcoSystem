"""Test fixtures for tests/code_scan/ (F-016, ADR-0019).

Self-provisioning DB readiness mirrors tests/compliance/conftest.py and
tests/bulk/conftest.py (the F-011/F-012a CI lesson): test packages run
alphabetically, so tests/code_scan/ runs BEFORE tests/compliance/ and
tests/persistence/ on a fresh CI DB.  This package provisions itself and is
DB-GATED: with no DATABASE_URL / APP_DATABASE_URL (or Postgres unreachable)
it is a no-op, so pure-unit tests (vectors 1-9) still run.

DB-backed tests (vector 12) require:
  - Live Postgres reachable via DATABASE_URL + APP_DATABASE_URL
  - SENTINEL_PROVISION_APP_ROLE=1

All secrets/PII/code in fixtures are synthetic and clearly marked.
No real credentials, no real API keys, no real code vulnerabilities in
fixture strings that would trip secret scanners on the repo itself.
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
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Load root .env so DATABASE_URL / APP_DATABASE_URL are available.
_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)

_SENTINEL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _parse_pg(url: str):
    return re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)


# ---------------------------------------------------------------------------
# Tenant identifiers
# ---------------------------------------------------------------------------


@pytest.fixture()
def test_tenant_id() -> str:
    return f"tenant-codescan-a-{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def tenant_b_id() -> str:
    return f"tenant-codescan-b-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# DB URL fixtures (skip cleanly when absent)
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        pytest.skip("DATABASE_URL not set — skipping DB-backed code_scan test")
    return _to_asyncpg_url(raw)


@pytest.fixture()
def app_db_url() -> str:
    raw = os.environ.get("APP_DATABASE_URL", "")
    if not raw:
        pytest.skip("APP_DATABASE_URL not set — skipping DB-backed code_scan test")
    return _to_asyncpg_url(raw)


# ---------------------------------------------------------------------------
# DB sessions
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def session(db_url: str) -> AsyncIterator[AsyncSession]:
    """Per-test privileged session (DATABASE_URL / BYPASSRLS)."""
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


@pytest_asyncio.fixture()
async def tenant_session(app_db_url: str, test_tenant_id: str) -> AsyncIterator[AsyncSession]:
    """Per-test RLS-scoped session (sentinel_app / NOBYPASSRLS)."""
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
# Engine-cache reset (per test — mirrors compliance/conftest.py pattern)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def _reset_db_engine_caches() -> AsyncIterator[None]:
    async def _dispose() -> None:
        import persistence.database as _db

        for _engine_attr, _factory_attr in (
            ("_app_engine", "_app_session_factory"),
            ("_privileged_engine", "_privileged_session_factory"),
        ):
            _engine = getattr(_db, _engine_attr, None)
            if _engine is not None:
                try:
                    await _engine.dispose()
                except Exception:
                    pass
            setattr(_db, _engine_attr, None)
            setattr(_db, _factory_attr, None)

    # SETUP reset: dispose any engine singleton leaked from a prior package/test
    # (a gateway/orchestration test monkeypatches APP_DATABASE_URL to a fake host
    # and builds the singleton; the env reverts at teardown but the cached engine
    # does NOT — f-019). Reset here so THIS test builds a fresh engine from the
    # current env in its own loop, regardless of what ran before.
    await _dispose()
    yield
    await _dispose()


# ---------------------------------------------------------------------------
# DB readiness (self-provisioning — mirrors bulk/conftest.py pattern)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _ensure_code_scan_db_ready() -> AsyncIterator[None]:
    """Session-autouse: provision schema + sentinel_app before DB tests run.

    DB-GATED: if DATABASE_URL/APP_DATABASE_URL are absent or Postgres is
    unreachable, this is a no-op so pure-unit tests run without a database.
    """
    db_url_raw = os.environ.get("DATABASE_URL", "")
    app_url_raw = os.environ.get("APP_DATABASE_URL", "")
    if not db_url_raw or not app_url_raw:
        yield
        return

    m = _parse_pg(db_url_raw)
    if not m:
        yield
        return

    import asyncpg

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
        yield  # Postgres unreachable → DB tests skip via their own guards
        return

    # 1) Schema at head.
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
        pytest.fail(f"_ensure_code_scan_db_ready: alembic upgrade head failed:\n{result.stderr}")

    # 2) Provision sentinel_app password (SCRAM verifier — plaintext never in SQL).
    app_pw_m = re.match(r"postgresql(?:\+asyncpg)?://[^:]+:([^@]+)@", app_url_raw)
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


# ---------------------------------------------------------------------------
# Mock HookContext factory
# ---------------------------------------------------------------------------


def make_mock_context(
    *,
    tenant_id: str = "tenant-test-001",
    is_stream: bool = False,
    session: Any = None,
) -> MagicMock:
    """Return a MagicMock HookContext for unit tests.

    emit() is an AsyncMock so tests can await it and assert calls.
    _is_stream is set to the literal bool (not a MagicMock) so the
    ``is True`` guard in detector.py works correctly.
    """
    ctx = MagicMock()
    ctx.tenant_context.tenant_id = tenant_id
    ctx._is_stream = is_stream
    ctx._db_session = session
    ctx.emit = AsyncMock(return_value=True)
    return ctx


from typing import Any  # noqa: E402 — needed for the fixture above
