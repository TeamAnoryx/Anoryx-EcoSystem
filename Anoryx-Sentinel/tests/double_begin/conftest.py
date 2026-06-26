"""DB-gated harness for the F-007-FU double-begin fix (ADR-0026).

Proves the two fail-open siblings on a REAL autobegin-ing get_tenant_session. The
entry points (_fetch_team_rpm_limit_from_db, bind_egress_context) open their OWN
tenant session, so the test policy row must be COMMITTED cross-session — the
persistence `session` fixture is rollback-only and cannot be used here (its conftest
says committed-data tests must manage their own connections).

Self-provisioning + DB-gated, mirroring tests/shadow_ai/conftest.py: provisions the
schema + sentinel_app password before its DB tests run, and skips the DB-backed
tests when Postgres is unreachable so the monkeypatched (no-DB) tests still run.

Requires: DATABASE_URL (superuser) + APP_DATABASE_URL (sentinel_app) in root .env
and SENTINEL_PROVISION_APP_ROLE=1.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import os
import re
import socket
import subprocess
import sys
import uuid
from typing import AsyncIterator

import pytest
import pytest_asyncio
from dotenv import load_dotenv

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)

_SENTINEL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _parse_pg(url: str):
    return re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)


def _make_async_url(raw_url: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw_url)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


@pytest_asyncio.fixture(autouse=True)
async def _reset_db_engine_caches() -> AsyncIterator[None]:
    """Dispose + null persistence.database engine caches around each test.

    asyncio_mode=auto uses a per-function event loop; the module-global engines bind
    to the loop of first use, so a stale pool from a prior test/package (e.g. one
    that monkeypatched APP_DATABASE_URL to a fake host) would hit 'Event loop is
    closed' or connect to the wrong host. Reset so this test builds a fresh engine
    from the current env in its own loop (mirrors tests/shadow_ai/conftest.py).
    """

    async def _dispose() -> None:
        import persistence.database as _db

        for _engine_attr, _factory_attr in (
            ("_app_engine", "_app_session_factory"),
            ("_privileged_engine", "_privileged_session_factory"),
        ):
            _engine = getattr(_db, _engine_attr, None)
            if _engine is not None:
                with contextlib.suppress(Exception):
                    await _engine.dispose()
            setattr(_db, _engine_attr, None)
            setattr(_db, _factory_attr, None)

    await _dispose()
    yield
    await _dispose()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _ensure_double_begin_db_ready() -> AsyncIterator[None]:
    """Session-autouse: provision schema + sentinel_app before DB tests run."""
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
        yield  # Postgres unreachable -> DB tests skip via db_ready
        return

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
        pytest.fail(f"_ensure_double_begin_db_ready: alembic upgrade head failed:\n{result.stderr}")

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


def _pg_reachable() -> bool:
    db_url_raw = os.environ.get("DATABASE_URL", "")
    app_url_raw = os.environ.get("APP_DATABASE_URL", "")
    if not db_url_raw or not app_url_raw:
        return False
    m = _parse_pg(db_url_raw)
    if not m:
        return False
    try:
        with socket.create_connection((m.group(3), int(m.group(4))), timeout=3):
            return True
    except OSError:
        return False


@pytest.fixture
def db_ready() -> None:
    """Skip a DB-backed test when Postgres is unreachable / env is unset."""
    if not _pg_reachable():
        pytest.skip("Postgres (DATABASE_URL/APP_DATABASE_URL) not reachable — DB-gated test")


@contextlib.asynccontextmanager
async def committed_routing_policy(
    *,
    tenant_id: str,
    team_id: str | None = None,
    allowed_providers: str = "openai",
    team_rpm_limit: int | None = None,
) -> AsyncIterator[None]:
    """Insert + COMMIT a tenant + its tenant_routing_policy row, then clean up.

    Commits via the privileged (DATABASE_URL / BYPASSRLS) role on its own engine so
    the row is visible to a separate get_tenant_session opened by the code under
    test. Column set mirrors tests/persistence/test_classifier_config._insert_policy
    (a proven-valid minimal insert) plus team_rpm_limit.
    """
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    team_id = team_id or str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    engine = create_async_engine(_make_async_url(os.environ["DATABASE_URL"]), pool_pre_ping=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, is_active) "
                    "VALUES (:t, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
                ),
                {"t": tenant_id, "n": "T " + tenant_id[:8]},
            )
            await conn.execute(
                text(
                    "INSERT INTO tenant_routing_policy "
                    "(tenant_id, team_id, project_id, agent_id, allowed_providers, "
                    " fallback_order, classifier_model_id, audit_mode, team_rpm_limit) "
                    "VALUES (:t, :team, :proj, 'gateway-core', :ap, :fb, NULL, 'full', :trl)"
                ),
                {
                    "t": tenant_id,
                    "team": team_id,
                    "proj": project_id,
                    "ap": allowed_providers,
                    "fb": allowed_providers,
                    "trl": team_rpm_limit,
                },
            )
        yield
    finally:
        async with engine.begin() as conn:
            await conn.execute(
                text("DELETE FROM tenant_routing_policy WHERE tenant_id = :t"), {"t": tenant_id}
            )
            await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tenant_id})
        await engine.dispose()


@pytest.fixture
def routing_policy(db_ready):
    """Return the committed_routing_policy context manager (DB-gated via db_ready)."""
    return committed_routing_policy
