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


# =========================================================================== #
# O-004 policy-distribution e2e: Sentinel-side DB standup + signing / shim / enforce
# helpers. APPENDED to the O-003 ingest harness above (no edits to it). This block
# stands up a SEPARATE Sentinel database (DATABASE_URL / APP_DATABASE_URL, distinct
# from the ORCH_* orchestrator DB) on the same Postgres host, runs Sentinel's own
# `alembic upgrade head`, provisions the sentinel_app SCRAM password, and exposes a
# real-loopback shim running Sentinel's REAL intake plus helpers that call Sentinel's
# REAL enforcement. Gated on the Sentinel DB being configured + reachable, so the
# orchestrator-only integration tests still run when it is not.
# =========================================================================== #

import json as _json  # noqa: E402
import threading as _threading  # noqa: E402
import time as _time  # noqa: E402
import uuid as _uuid  # noqa: E402

# asyncpg's SSL-probe fallback can raise ConnectionResetError on Windows; PGSSLMODE=disable
# makes asyncpg skip the probe for the Sentinel engine (which, unlike the orchestrator
# engine, has no ssl=False knob). Harmless on Linux/CI (local PG has TLS off). Our own
# raw-asyncpg + dedicated-engine helpers pass ssl=False explicitly regardless.
os.environ.setdefault("PGSSLMODE", "disable")

# Make Sentinel's src importable (top-level `policy`, `persistence`) for the non-stubbed
# e2e. Inserted FIRST so Sentinel's packages win over any stray same-named distribution.
# CI additionally `pip install -e Anoryx-Sentinel[dev]`; this is the belt-and-suspenders
# fallback for a bare-PYTHONPATH local run.
_SENTINEL_ROOT = os.path.abspath(os.path.join(_ORCH_ROOT, "..", "Anoryx-Sentinel"))
_SENTINEL_SRC = os.path.join(_SENTINEL_ROOT, "src")
if _SENTINEL_SRC not in sys.path:
    sys.path.insert(0, _SENTINEL_SRC)

# Test-only tokens (fakes, never production secrets) + the documented intake path.
SENTINEL_ADMIN_TOKEN = "o004-sentinel-admin-token"  # noqa: S105 - test-only fake
SENTINEL_INTAKE_PATH = "/admin/policies/intake"


def _sentinel_pg_reachable() -> bool:
    """True iff DATABASE_URL + APP_DATABASE_URL (the Sentinel DB) are set and reachable."""
    db_url = os.environ.get("DATABASE_URL", "")
    app_url = os.environ.get("APP_DATABASE_URL", "")
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


def _run_sentinel_alembic(*args: str) -> subprocess.CompletedProcess:
    """Run Sentinel's `alembic <args>` (sync psycopg) with DATABASE_URL → sentinel DB."""
    env = os.environ.copy()
    env["PYTHONPATH"] = _SENTINEL_SRC
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=_SENTINEL_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )


def _provision_sentinel_app_role() -> None:
    """ALTER ROLE sentinel_app with a SCRAM verifier derived from APP_DATABASE_URL (sync).

    Mirrors _provision_app_role above: the migration creates a passwordless sentinel_app
    role, and this sets its SCRAM password to the one embedded in APP_DATABASE_URL so the
    enforcement helper can log in as that NOBYPASSRLS role. Sync psycopg only (never touches
    asyncpg from the session-scoped harness).
    """
    app_url = os.environ.get("APP_DATABASE_URL", "")
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
    with psycopg.connect(_sync_dsn(os.environ["DATABASE_URL"]), autocommit=True) as conn:
        conn.execute(f"ALTER ROLE sentinel_app WITH LOGIN PASSWORD '{verifier}'")  # noqa: S608


@pytest.fixture(scope="session", autouse=True)
def _ensure_sentinel_db_ready(_ensure_db_ready) -> None:
    """Provision the Sentinel schema + sentinel_app password before the e2e runs (sync).

    Depends on _ensure_db_ready so the orchestrator schema is stood up first. No-ops when
    the Sentinel DB is not configured/reachable (the orchestrator-only integration tests
    then still run; the distribution e2e skips via sentinel_db_ready).
    """
    if not _sentinel_pg_reachable():
        return
    result = _run_sentinel_alembic("upgrade", "head")
    if result.returncode != 0:
        pytest.fail(
            f"_ensure_sentinel_db_ready: sentinel alembic upgrade head failed:\n{result.stderr}"
        )
    _provision_sentinel_app_role()


@pytest.fixture
def sentinel_db_ready(db_ready) -> None:
    """Skip a distribution-e2e test when the Sentinel DB is not reachable (or ORCH DB unset)."""
    if not _sentinel_pg_reachable():
        pytest.skip("Sentinel DB (DATABASE_URL/APP_DATABASE_URL) not reachable — distribution e2e")


@pytest.fixture(scope="session")
def sentinel_signing(tmp_path_factory):
    """Generate an ES256 keypair at runtime, expose its pubkey to intake, yield the private key.

    Writes the SPKI public key PEM to a temp file and points POLICY_SIGNING_PUBKEY_PATH at it,
    then resets Sentinel's load-once key cache so the shim's intake verifies against THIS key.
    Session-scoped: one signing key for the whole e2e run (intake caches the verifying key, so
    it must be stable across the session). Keys are generated in-memory at runtime — no PEM
    literal ever appears in source.
    """
    from policy import crypto

    private_key, public_key = crypto.generate_keypair()
    pub_path = tmp_path_factory.mktemp("o004_policy_keys") / "policy_pub.pem"
    pub_path.write_bytes(crypto.public_key_to_pem(public_key))
    os.environ["POLICY_SIGNING_PUBKEY_PATH"] = str(pub_path)
    os.environ["SENTINEL_ADMIN_TOKEN"] = SENTINEL_ADMIN_TOKEN
    crypto.reset_key_cache_for_testing()
    try:
        yield private_key
    finally:
        crypto.reset_key_cache_for_testing()


@pytest.fixture(scope="session")
def sentinel_shim_server(sentinel_signing, _ensure_sentinel_db_ready):
    """Run the TEST Sentinel intake shim on a REAL loopback uvicorn server; yield its base URL.

    A genuine ephemeral TCP socket so the Orchestrator engine's outbound httpx call is
    non-stubbed (real httpx → real socket → uvicorn → shim → Sentinel's real intake). The
    shim runs in a daemon thread with its own event loop; the Sentinel privileged engine it
    uses binds to THAT loop (the test never touches Sentinel's singletons — it uses raw
    asyncpg + a dedicated engine in the pytest loop). Yields None when the Sentinel DB is
    unconfigured so the fixture is harmless in that case.
    """
    if not _sentinel_pg_reachable():
        yield None
        return

    import uvicorn
    from _sentinel_shim import create_shim_app

    app = create_shim_app(SENTINEL_INTAKE_PATH)
    # http="h11" (pure-Python) + ws="none" + lifespan="off" make the threaded test server
    # deterministic: the httptools/websockets path is the source of intermittent response
    # resets for a uvicorn server run in a background thread on Windows (a lost response would
    # trip the engine's at-least-once retry → a duplicate intake → Sentinel replay-reject).
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        log_level="warning",
        lifespan="off",
        http="h11",
        ws="none",
    )
    server = uvicorn.Server(config)
    thread = _threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = _time.time() + 30
    while not server.started and _time.time() < deadline:
        _time.sleep(0.05)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        pytest.fail("sentinel shim server did not start within 30s")

    port = server.servers[0].sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    try:
        yield base_url
    finally:
        server.should_exit = True
        thread.join(timeout=5)


@pytest.fixture
def make_signed_policy(sentinel_signing):
    """Return a factory(policy_type, *, tenant_id, ...) → a byte-valid SIGNED policy record.

    Produces the record via Sentinel's REAL sign path (crypto.sign_policy_record → ES256 JWS
    over the eight scope claims + a content hash of the whole record). Defaults team/project
    to the wildcard UUID and agent to WILDCARD_AGENT so the policy matches ANY request scope
    under tenant_id (no exact sub-id match needed). effective_from is in the past so the
    policy is active. tamper_signature=True flips one base64url char in the JWS signature
    segment (still schema-pattern-valid, but ES256 verification fails → RejectedSignature).
    """
    from policy import crypto
    from policy.constants import WILDCARD_AGENT, WILDCARD_UUID

    def _factory(
        policy_type: str,
        *,
        tenant_id: str,
        allowed_model_ids: list[str] | None = None,
        denied_model_ids: list[str] | None = None,
        reason: str | None = None,
        policy_id: str | None = None,
        policy_version: int = 1,
        effective_from: str = "2020-01-01T00:00:00Z",
        team_id: str | None = None,
        project_id: str | None = None,
        agent_id: str | None = None,
        tamper_signature: bool = False,
    ) -> dict:
        record: dict = {
            "policy_type": policy_type,
            "tenant_id": tenant_id,
            "team_id": team_id or WILDCARD_UUID,
            "project_id": project_id or WILDCARD_UUID,
            "agent_id": agent_id or WILDCARD_AGENT,
            "policy_id": policy_id or str(_uuid.uuid4()),
            "policy_version": policy_version,
            "effective_from": effective_from,
        }
        if policy_type == "model_allowlist":
            record["allowed_model_ids"] = allowed_model_ids or ["gpt-4o-mini"]
        elif policy_type == "model_denylist":
            record["denied_model_ids"] = denied_model_ids or []
            record["reason"] = reason or "blocked for the O-004 distribution e2e"
        signed = crypto.sign_policy_record(record, sentinel_signing)
        if tamper_signature:
            head, payload, mac = signed["signature"].split(".")
            flipped = ("B" if mac[0] != "B" else "C") + mac[1:]
            signed = dict(signed)
            signed["signature"] = f"{head}.{payload}.{flipped}"
        return signed

    return _factory


def _sentinel_asyncpg_conn(url_env: str):
    """Open a raw asyncpg connection (ssl off) for the given Sentinel URL env var name."""
    import asyncpg

    m = _parse_pg(os.environ[url_env])
    return asyncpg.connect(
        user=m.group(1),
        password=m.group(2),
        host=m.group(3),
        port=int(m.group(4)),
        database=m.group(5),
        ssl=False,
    )


@pytest.fixture
def seed_sentinel_tenant():
    """Return an async callable that INSERTs+commits a Sentinel `tenants` row (raw asyncpg).

    The policies.tenant_id FK → tenants.tenant_id requires the tenant to exist before intake
    can persist a policy. Committed via the privileged Sentinel role on its own connection so
    the row is visible to the shim's separate intake connection.
    """

    async def _seed(tenant_id: str) -> None:
        conn = await _sentinel_asyncpg_conn("DATABASE_URL")
        try:
            await conn.execute(
                "INSERT INTO tenants (tenant_id, name, is_active) VALUES ($1, $2, true) "
                "ON CONFLICT (tenant_id) DO NOTHING",
                tenant_id,
                "T " + tenant_id[:8],
            )
        finally:
            await conn.close()

    return _seed


@pytest.fixture
def read_sentinel_policy_signature():
    """Return an async callable reading back a persisted policies.signature (raw asyncpg)."""

    async def _read(policy_id: str) -> str | None:
        conn = await _sentinel_asyncpg_conn("DATABASE_URL")
        try:
            return await conn.fetchval(
                "SELECT signature FROM policies WHERE policy_id = $1", policy_id
            )
        finally:
            await conn.close()

    return _read


@pytest.fixture
def sentinel_enforce():
    """Return an async callable that runs Sentinel's REAL evaluate_model_policies for a scope.

    Builds a DEDICATED SQLAlchemy app engine (sentinel_app role, ssl off, NullPool) in the
    test's own loop, sets the transaction-local tenant GUC, and calls Sentinel's real
    enforcement entrypoint — the exact RLS-scoped read path the gateway uses. Returns a
    ModelDecision (ModelAllow | ModelDeny). A dedicated engine (not Sentinel's singleton)
    keeps the read in the pytest loop, isolated from the shim's uvicorn-thread engine.
    """

    async def _enforce(
        tenant_id: str,
        model_id: str,
        *,
        team_id: str | None = None,
        project_id: str | None = None,
        agent_id: str = "gateway-core",
    ):
        from policy.enforcement import RequestScope, evaluate_model_policies
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )
        from sqlalchemy.pool import NullPool

        url = re.sub(
            r"^postgresql(?:\+\w+)?://",
            "postgresql+asyncpg://",
            os.environ["APP_DATABASE_URL"],
        )
        engine = create_async_engine(url, connect_args={"ssl": False}, poolclass=NullPool)
        maker = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with maker() as session:
                await session.execute(
                    text("SELECT set_config('app.current_tenant_id', :t, true)"),
                    {"t": tenant_id},
                )
                scope = RequestScope(
                    tenant_id=tenant_id,
                    team_id=team_id or str(_uuid.uuid4()),
                    project_id=project_id or str(_uuid.uuid4()),
                    agent_id=agent_id,
                )
                return await evaluate_model_policies(session, scope, model_id)
        finally:
            await engine.dispose()

    return _enforce


@pytest.fixture
def seed_distribution():
    """Return an async callable that persists a PENDING orchestrator distribution + targets.

    Mirrors the router's durable persist (insert distribution → targets → a `submitted` audit
    link) WITHOUT going through HTTP, so a subsequent explicit drive_distribution is the only
    distribution (deterministic — no FastAPI BackgroundTask double-fire). Writes commit on the
    orchestrator tenant + privileged sessions.
    """

    async def _seed(
        *,
        distribution_id: str,
        tenant_id: str,
        signed_record: dict,
        sentinel_ids: list[str],
        max_attempts: int = 2,
    ) -> None:
        from orchestrator.persistence import repositories as repo
        from orchestrator.persistence.database import (
            get_privileged_session,
            get_tenant_session,
        )

        policy_id = signed_record["policy_id"]
        content_hash = hashlib.sha256(
            _json.dumps(signed_record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        async with get_tenant_session(tenant_id) as session:
            await repo.insert_policy_distribution(
                session,
                {
                    "distribution_id": distribution_id,
                    "policy_id": policy_id,
                    "policy_version": signed_record["policy_version"],
                    "tenant_id": tenant_id,
                    "policy_type": signed_record["policy_type"],
                    "state": "pending",
                    "signed_record": signed_record,
                    "content_hash": content_hash,
                },
            )
            for sentinel_id in sentinel_ids:
                await repo.insert_distribution_target(
                    session,
                    {
                        "target_id": _uuid.uuid4().hex,
                        "distribution_id": distribution_id,
                        "tenant_id": tenant_id,
                        "sentinel_id": sentinel_id,
                        "state": "pending",
                        "attempt_count": 0,
                        "max_attempts": max_attempts,
                    },
                )
            await session.commit()
        async with get_privileged_session() as psession:
            async with psession.begin():
                await repo.append_distribution_audit_link(
                    psession,
                    {
                        "distribution_id": distribution_id,
                        "policy_id": policy_id,
                        "tenant_id": tenant_id,
                        "policy_type": signed_record["policy_type"],
                    },
                    disposition="submitted",
                )

    return _seed
