"""DB-gated harness for the O-003 ingest pipeline integration tests (ADR-0003).

Ported from Anoryx-Sentinel/tests/double_begin/conftest.py. Self-provisioning + DB-gated:
provisions the schema (alembic upgrade head) + the orchestrator_app SCRAM password before
its DB tests run, and skips them when Postgres is unreachable so the rest of the suite
(unit + contract) still runs.

Requires: ORCH_DATABASE_URL (privileged/superuser) + ORCH_APP_DATABASE_URL
(orchestrator_app) in the environment + ORCH_PROVISION_APP_ROLE=1.

WINDOWS EVENT LOOP: asyncpg connection teardown under the default Windows
ProactorEventLoop races and raises ConnectionResetError [WinError 64] at loop close. The
SelectorEventLoop tears down asyncpg sockets cleanly. We force the selector policy on
win32 so the same suite is green locally (Windows) and on CI (Linux already uses selector).

ENGINE RESET (ADR-0026 / F-007 lesson): the module-global engines bind to the event loop
of first use; asyncio_mode=auto uses a per-function loop, so a stale pool from a prior
test would hit 'Event loop is closed' or a stale-DSN host. reset_engines() runs BEFORE and
after each test so each builds a fresh engine from the current env in its own loop.

The session-scoped provisioning is fully SYNC (subprocess alembic + psycopg) so it never
shares an asyncpg connection across the per-function test loops.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import os
import re
import socket
import subprocess
import sys
from typing import AsyncIterator

import pytest
import pytest_asyncio
from dotenv import load_dotenv

if sys.platform == "win32":
    with contextlib.suppress(Exception):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

_HERE = os.path.dirname(__file__)
_ORCH_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))  # Anoryx-AI-Orchestrator
_ENV_PATH = os.path.join(_ORCH_ROOT, "..", ".env")  # repo-root .env (best-effort)
load_dotenv(dotenv_path=_ENV_PATH)


def _parse_pg(url: str):
    return re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)


def _sync_dsn(url: str) -> str:
    """Strip any async/driver suffix so psycopg / libpq accepts the conninfo URL."""
    return re.sub(r"^postgresql\+\w+://", "postgresql://", url)


def _run_alembic(*args: str) -> subprocess.CompletedProcess:
    """Run `alembic <args>` (sync psycopg) with ORCH_DATABASE_URL in the environment."""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(_ORCH_ROOT, "src")
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=_ORCH_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _provision_app_role() -> None:
    """ALTER ROLE orchestrator_app with a SCRAM verifier from ORCH_APP_DATABASE_URL (sync).

    Idempotent; opt-in via ORCH_PROVISION_APP_ROLE=1 (CI/local ephemeral only). Needed
    after every `alembic upgrade head` that (re)creates the passwordless role. Uses a sync
    psycopg connection so the session-scoped harness never touches asyncpg.
    """
    if os.environ.get("ORCH_PROVISION_APP_ROLE") != "1":
        return
    app_url = os.environ.get("ORCH_APP_DATABASE_URL", "")
    app_pw_m = re.match(r"postgresql(?:\+asyncpg)?://[^:]+:([^@]+)@", app_url)
    if not app_pw_m:
        return

    import psycopg

    app_password = app_pw_m.group(1)
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
    with psycopg.connect(_sync_dsn(os.environ["ORCH_DATABASE_URL"]), autocommit=True) as conn:
        conn.execute(f"ALTER ROLE orchestrator_app WITH PASSWORD '{verifier}'")  # noqa: S608


def _pg_reachable() -> bool:
    db_url = os.environ.get("ORCH_DATABASE_URL", "")
    app_url = os.environ.get("ORCH_APP_DATABASE_URL", "")
    if not db_url or not app_url:
        return False
    m = _parse_pg(db_url)
    if not m:
        return False
    try:
        with socket.create_connection((m.group(3), int(m.group(4))), timeout=3):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session", autouse=True)
def _ensure_db_ready() -> None:
    """Provision schema + orchestrator_app password before the DB tests run (sync)."""
    if not _pg_reachable():
        return  # Postgres unreachable / env unset -> DB tests skip via db_ready
    result = _run_alembic("upgrade", "head")
    if result.returncode != 0:
        pytest.fail(f"_ensure_db_ready: alembic upgrade head failed:\n{result.stderr}")
    _provision_app_role()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _reset_db_engine_caches() -> AsyncIterator[None]:
    """Dispose + null the persistence engine singletons once per session.

    With a session-scoped event loop the engines bind to that one loop and stay valid for
    the whole run, so a clean slate before + a dispose after the session is sufficient (a
    per-test dispose would churn connections on the shared loop for no benefit).
    """
    from orchestrator.persistence import database as db

    await db.reset_engines()
    yield
    await db.reset_engines()


@pytest.fixture
def db_ready() -> None:
    """Skip a DB-backed test when Postgres is unreachable / ORCH_* unset."""
    if not _pg_reachable():
        pytest.skip("Postgres (ORCH_DATABASE_URL/ORCH_APP_DATABASE_URL) not reachable")


@contextlib.asynccontextmanager
async def _open_privileged_conn() -> AsyncIterator[object]:
    """A raw asyncpg connection on the privileged URL (BYPASSRLS) for test assertions."""
    import asyncpg

    m = _parse_pg(os.environ["ORCH_DATABASE_URL"])
    # ssl=False: local/CI Postgres has TLS off; on Windows asyncpg's SSL-probe fallback can
    # raise ConnectionResetError. The privileged URL is a local/ephemeral test DB.
    conn = await asyncpg.connect(
        user=m.group(1),
        password=m.group(2),
        host=m.group(3),
        port=int(m.group(4)),
        database=m.group(5),
        ssl=False,
    )
    try:
        yield conn
    finally:
        await conn.close()


@pytest_asyncio.fixture
async def db_conn(db_ready) -> AsyncIterator[object]:
    """A live privileged (BYPASSRLS) asyncpg connection for cross-tenant test assertions."""
    async with _open_privileged_conn() as conn:
        yield conn


@contextlib.asynccontextmanager
async def _open_app_conn() -> AsyncIterator[object]:
    """A raw asyncpg connection as orchestrator_app (NOBYPASSRLS), for RLS assertions.

    This is the same role + RLS the runtime get_tenant_session uses; a raw asyncpg conn
    exercises the DB-level isolation directly (and avoids the SQLAlchemy-greenlet asyncpg
    path that is flaky on Windows when driven from the bare test coroutine).
    """
    import asyncpg

    m = _parse_pg(os.environ["ORCH_APP_DATABASE_URL"])
    conn = await asyncpg.connect(
        user=m.group(1),
        password=m.group(2),
        host=m.group(3),
        port=int(m.group(4)),
        database=m.group(5),
        ssl=False,
    )
    try:
        yield conn
    finally:
        await conn.close()


@pytest_asyncio.fixture
async def app_db_conn(db_ready) -> AsyncIterator[object]:
    """A live orchestrator_app (NOBYPASSRLS) asyncpg connection for live RLS assertions."""
    async with _open_app_conn() as conn:
        yield conn


@pytest.fixture
def run_alembic(db_ready):
    """Expose the alembic runner to tests (e.g. the migration round-trip)."""
    return _run_alembic


@pytest.fixture
def reprovision_app_role(db_ready):
    """Expose the (sync) app-role re-provisioner (after a downgrade/upgrade drops it)."""
    return _provision_app_role
