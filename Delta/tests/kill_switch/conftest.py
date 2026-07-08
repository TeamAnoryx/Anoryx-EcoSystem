"""Fixtures for the D-006 kill-switch DB suite.

Mirrors the proven D-005 DB harness (``tests/budget_engine/conftest.py``): one
``alembic upgrade head`` per session (now through migration 0004), per-test SCRAM
provisioning of ``delta_app``, and a privileged TRUNCATE before each test that resets the
D-006 tables (plus the shared ledger tables the D-004 posting path writes). Every test
uses a fresh random tenant, so committed rows never collide and RLS keeps each test's view
to its own tenant. The DB-touching autouse fixtures NO-OP when
``DATABASE_URL``/``APP_DATABASE_URL`` are unset so the pure-unit modules (``triggers.py``)
still run with no Postgres.

Reuses the exact same session-scoped signing-key fixture pattern as D-005: a fresh ECDSA
P-256 key is generated once per test session and injected via
``DELTA_POLICY_SIGNING_PRIVATE_KEY_PEM`` (the kill-switch signs with the SAME Delta
identity D-005 uses — no new key custody surface).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from delta.kill_switch.config import KillSwitchSettings

_DELTA_ROOT = Path(__file__).resolve().parents[2]  # .../Delta


def _asyncpg(url: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", url)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _parse(url: str) -> dict:
    m = re.match(r"postgresql(?:\+\w+)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)
    if not m:
        pytest.fail("could not parse a postgres URL (user:pw@host:port/db expected)")
    return {
        "user": m.group(1),
        "password": m.group(2),
        "host": m.group(3),
        "port": int(m.group(4)),
        "database": m.group(5),
    }


def _factory(engine) -> async_sessionmaker:
    return async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False, autocommit=False
    )


def _db_env_present() -> bool:
    return bool(os.environ.get("DATABASE_URL") and os.environ.get("APP_DATABASE_URL"))


db_required = pytest.mark.skipif(
    not _db_env_present(), reason="DATABASE_URL/APP_DATABASE_URL unset (no live Postgres)"
)


# --------------------------------------------------------------------------- signing key
@pytest.fixture(scope="session", autouse=True)
def signing_key(tmp_path_factory) -> bytes:
    """Generate a P-256 signing key, inject the private PEM into env (same identity D-005
    signs with; no new key custody surface for D-006)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    os.environ["DELTA_POLICY_SIGNING_PRIVATE_KEY_PEM"] = priv_pem.decode("utf-8")

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = tmp_path_factory.mktemp("d006_keys") / "policy_pub.pem"
    pub_path.write_bytes(pub_pem)
    os.environ["POLICY_SIGNING_PUBKEY_PATH"] = str(pub_path)
    return priv_pem


@pytest.fixture
def kill_switch_settings() -> KillSwitchSettings:
    """Enabled kill-switch settings pointing at a dummy O-004 URL (DB tests stub the
    publisher). No anomaly ceiling by default — individual tests opt in."""
    return KillSwitchSettings(
        enabled=True,
        distribution_url="http://orch.invalid:9",
        service_token="test-token",
        max_publish_attempts=3,
        backoff_base_seconds=0.0,
        max_single_tx_cost_cents=None,
    )


# --------------------------------------------------------------------------- schema/provision
@pytest.fixture(scope="session", autouse=True)
def ensure_schema_at_head() -> None:
    if not os.environ.get("DATABASE_URL"):
        return
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(_DELTA_ROOT),
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}")


async def _provision_delta_app(db_url: str, app_url: str) -> None:
    import base64
    import hashlib
    import hmac as _hmac

    app_pw = _parse(app_url)["password"]
    d = _parse(db_url)
    import asyncpg

    conn = await asyncpg.connect(
        user=d["user"],
        password=d["password"],
        host=d["host"],
        port=d["port"],
        database=d["database"],
    )
    try:
        salt = os.urandom(16)
        iters = 4096
        salted = hashlib.pbkdf2_hmac("sha256", app_pw.encode(), salt, iters)
        ck = _hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        sk = _hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        verifier = (
            f"SCRAM-SHA-256${iters}"
            f":{base64.b64encode(salt).decode()}"
            f"${base64.b64encode(hashlib.sha256(ck).digest()).decode()}"
            f":{base64.b64encode(sk).decode()}"
        )
        await conn.execute(f"ALTER ROLE delta_app WITH LOGIN PASSWORD '{verifier}'")
        verify = await asyncpg.connect(
            user="delta_app",
            password=app_pw,
            host=d["host"],
            port=d["port"],
            database=d["database"],
        )
        await verify.close()
    finally:
        await conn.close()


@pytest_asyncio.fixture(autouse=True)
async def provision_app_role(ensure_schema_at_head: None) -> None:
    if os.environ.get("DELTA_PROVISION_APP_ROLE", "").lower() not in ("1", "true", "yes", "on"):
        return
    if not _db_env_present():
        return
    await _provision_delta_app(os.environ["DATABASE_URL"], os.environ["APP_DATABASE_URL"])


@pytest_asyncio.fixture(autouse=True)
async def _truncate(provision_app_role: None) -> AsyncIterator[None]:
    if not _db_env_present():
        yield
        return
    engine = create_async_engine(_asyncpg(os.environ["DATABASE_URL"]), poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "TRUNCATE delta.kill_switch_outbox, delta.kill_switch_state, "
                    "delta.agent_authorizations, delta.ledger_entries, delta.transactions, "
                    "delta.accounts, delta.ingest_dead_letter CASCADE"
                )
            )
    finally:
        await engine.dispose()
    yield


@pytest.fixture(autouse=True)
def _reset_delta_engines() -> Iterator[None]:
    from delta.persistence import database as _db

    _db.reset_engines()
    yield
    _db.reset_engines()


# --------------------------------------------------------------------------- tenants
@pytest.fixture
def tenant_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def other_tenant_id() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------------------------------- tenant session opener
def open_tenant_session(tenant_id: str):
    """A delta_app session with the tenant GUC set (RLS active)."""
    engine = create_async_engine(_asyncpg(os.environ["APP_DATABASE_URL"]), poolclass=NullPool)
    factory = _factory(engine)

    class _Ctx:
        async def __aenter__(self) -> AsyncSession:
            self._engine = engine
            self._session = factory()
            sess = await self._session.__aenter__()
            await sess.execute(
                text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": tenant_id}
            )
            return sess

        async def __aexit__(self, *exc) -> None:
            await self._session.__aexit__(*exc)
            await self._engine.dispose()

    return _Ctx()


@pytest.fixture
def tenant_session():
    return open_tenant_session


# --------------------------------------------------------------------------- usage / posting
@pytest.fixture
def make_usage_payload() -> Callable[..., dict]:
    def _make(
        tenant_id: str,
        *,
        team_id: str | None = None,
        project_id: str | None = None,
        agent_id: str = "gateway-core",
        cost: int = 1234,
        event_id: str | None = None,
    ) -> dict:
        return {
            "event_type": "usage",
            "tenant_id": tenant_id,
            "team_id": team_id or str(uuid.uuid4()),
            "project_id": project_id or str(uuid.uuid4()),
            "agent_id": agent_id,
            "event_id": event_id or str(uuid.uuid4()),
            "event_timestamp": "2026-07-01T12:00:00Z",
            "request_id": "req-" + uuid.uuid4().hex[:24],
            "model": "gpt-4o",
            "tokens_in": 10,
            "tokens_out": 20,
            "latency_ms": 5,
            "cost_estimate_cents": cost,
        }

    return _make


@pytest.fixture
def post_debit() -> Callable[[dict], Awaitable[object]]:
    async def _post(payload: dict):
        from delta.ingest.posting import build_usage_record, post_usage

        record = build_usage_record(payload)
        await post_usage(record)
        return record

    return _post


# --------------------------------------------------------------------------- readers
async def _read_outbox(tenant_id: str) -> list[dict]:
    async with open_tenant_session(tenant_id) as s:
        rows = (
            (
                await s.execute(
                    text(
                        "SELECT outbox_id, policy_id, policy_version, transition, state, "
                        "attempts, distribution_id, last_error FROM delta.kill_switch_outbox "
                        "ORDER BY created_at"
                    )
                )
            )
            .mappings()
            .all()
        )
        return [dict(r) for r in rows]


async def _read_state(tenant_id: str) -> list[dict]:
    async with open_tenant_session(tenant_id) as s:
        rows = (
            (
                await s.execute(
                    text(
                        "SELECT kill_id, team_id, project_id, agent_id, policy_id, state, "
                        "reason, last_published_version FROM delta.kill_switch_state "
                        "ORDER BY updated_at"
                    )
                )
            )
            .mappings()
            .all()
        )
        return [dict(r) for r in rows]


@pytest.fixture
def read_outbox() -> Callable[[str], Awaitable[list[dict]]]:
    return _read_outbox


@pytest.fixture
def read_state() -> Callable[[str], Awaitable[list[dict]]]:
    return _read_state
