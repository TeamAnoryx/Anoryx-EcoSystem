"""Fixtures for the Delta ledger persistence suite (D-003).

Connects to a live Postgres via DATABASE_URL (privileged owner) and APP_DATABASE_URL
(delta_app, NOBYPASSRLS), read from the environment — no Delta/.env is committed
(hook-protected). CI sets these in the job env; locally, export them (see
Delta/docker-compose.yml for the matching connection strings) or run the compose
stack.

ISOLATION MODEL (important): the balanced-invariant constraint trigger is DEFERRED to
COMMIT, so tests must really COMMIT to exercise it — the SAVEPOINT-rollback trick
used by stubbed suites would never fire the trigger. The ledger is also append-only
(no DELETE), so we cannot tidy rows per test either. Instead:
  - every test uses a fresh random tenant_id, so committed rows never collide and RLS
    keeps each test's view to its own tenant;
  - a session-start TRUNCATE (privileged role only — delta_app has no TRUNCATE grant)
    resets the tables so the DB does not grow unbounded across local re-runs.

The delta_app SCRAM password is provisioned per test (idempotent, ~50ms) — loud
pytest.fail on any provisioning error, never a silent swallow (the f-003b lesson).
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
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from account_seed import ensure_accounts, builder_account_id
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from delta.ledger import LedgerEntry
from delta.money import Money

_DELTA_ROOT = Path(__file__).resolve().parent.parent.parent  # .../Delta

# Shared fixed instant for the persistence-layer builders (matches tests/conftest.py).
_FIXED_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


def _require(name: str) -> str:
    raw = os.environ.get(name, "")
    if not raw:
        pytest.fail(
            f"{name} is not set. The Delta persistence suite needs a live Postgres. "
            f"Export DATABASE_URL (owner) and APP_DATABASE_URL (delta_app), or run "
            f"Delta/docker-compose.yml. See Delta/docker-compose.yml for the URLs."
        )
    return raw


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


@pytest.fixture(scope="session", autouse=True)
def ensure_schema_at_head() -> None:
    """Run `alembic upgrade head` once before any persistence test."""
    _require("DATABASE_URL")
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
    """Provision delta_app's SCRAM password (idempotent). Loud failure on any error."""
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
        ck = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
        sk = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        verifier = (
            f"SCRAM-SHA-256${iters}"
            f":{base64.b64encode(salt).decode()}"
            f"${base64.b64encode(hashlib.sha256(ck).digest()).decode()}"
            f":{base64.b64encode(sk).decode()}"
        )
        await conn.execute(f"ALTER ROLE delta_app WITH LOGIN PASSWORD '{verifier}'")
        # Self-check: prove delta_app authenticates with the plaintext now.
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
    """Re-provision delta_app's password before each test (idempotent, cheap).

    Async (awaited in the test's event loop) — NOT asyncio.run() in a sync fixture,
    which closes the loop and breaks pytest-asyncio's subsequent get_event_loop().
    """
    if os.environ.get("DELTA_PROVISION_APP_ROLE", "").lower() not in ("1", "true", "yes", "on"):
        return
    await _provision_delta_app(_require("DATABASE_URL"), _require("APP_DATABASE_URL"))


@pytest_asyncio.fixture(scope="function", autouse=True)
async def _truncate_ledger(provision_app_role: None) -> AsyncIterator[None]:
    """Reset the ledger tables before each test (privileged TRUNCATE).

    delta_app has no TRUNCATE grant, so only the harness can do this. Combined with a
    fresh per-test tenant_id this gives clean, real-commit tests on an append-only
    ledger.
    """
    engine = create_async_engine(_asyncpg(_require("DATABASE_URL")), poolclass=None)
    async with engine.begin() as conn:
        await conn.execute(
            text("TRUNCATE delta.ledger_entries, delta.transactions, delta.accounts CASCADE")
        )
    await engine.dispose()
    yield


@pytest.fixture
def tenant_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def other_tenant_id() -> str:
    return str(uuid.uuid4())


@pytest_asyncio.fixture
async def privileged_engine() -> AsyncIterator[object]:
    engine = create_async_engine(_asyncpg(_require("DATABASE_URL")), echo=False)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def app_engine() -> AsyncIterator[object]:
    engine = create_async_engine(_asyncpg(_require("APP_DATABASE_URL")), echo=False)
    yield engine
    await engine.dispose()


def _factory(engine) -> async_sessionmaker:
    return async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False, autocommit=False
    )


@pytest_asyncio.fixture
async def privileged_session(privileged_engine) -> AsyncIterator[AsyncSession]:
    async with _factory(privileged_engine)() as session:
        yield session


def open_tenant_session(engine, tenant_id: str):
    """Async context manager: a delta_app session with the tenant GUC set.

    Use for the primary tenant and for opening a SECOND tenant's session in isolation
    tests. RLS is active (delta_app is NOBYPASSRLS).
    """
    factory = _factory(engine)

    class _Ctx:
        async def __aenter__(self) -> AsyncSession:
            self._session = factory()
            sess = await self._session.__aenter__()
            await sess.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": tenant_id},
            )
            # D-004: seed the two deterministic builder accounts so the same-tenant FK
            # on ledger_entries is satisfied for any make_entry/make_balanced_txn post.
            # Idempotent (ON CONFLICT DO NOTHING); uncommitted here, committed with the
            # test's own write (or harmlessly discarded on a read-only session).
            # Skip for an empty/whitespace tenant — that is the fail-closed empty-GUC
            # case (tests assert RLS returns zero rows), where an account INSERT would
            # be (correctly) rejected by the WITH CHECK predicate.
            if tenant_id and tenant_id.strip():
                await ensure_accounts(
                    sess,
                    tenant_id,
                    builder_account_id(tenant_id, "debit"),
                    builder_account_id(tenant_id, "credit"),
                )
            return sess

        async def __aexit__(self, *exc) -> None:
            await self._session.__aexit__(*exc)

    return _Ctx()


@pytest.fixture
def tenant_db(app_engine, tenant_id: str):
    """Open a fresh delta_app session for the test's tenant.

    Returns a zero-arg opener. Open a NEW session per logical step:
    ``append_transaction`` COMMITs, which clears the transaction-local GUC, so a
    write and a subsequent read must each run in their own ``async with`` (this is
    exactly how a tenant session is used in production).

        async with tenant_db() as s:
            await append_transaction(s, txn)
        async with tenant_db() as s:               # fresh GUC, fresh snapshot
            bal = await account_balance(s, account_id)
    """
    return lambda: open_tenant_session(app_engine, tenant_id)


@pytest.fixture
def tenant_db_for(app_engine):
    """Open a delta_app session for an ARBITRARY tenant_id (isolation tests).

    Returns a callable ``(tenant_id) -> async context manager``; use it to open a
    second tenant's session and assert cross-tenant invisibility.
    """
    return lambda tid: open_tenant_session(app_engine, tid)


@pytest.fixture
def make_entry():
    """DB-layer override of the parent make_entry (D-004).

    Identical to ``tests/conftest.py`` except the ``account_id`` is DETERMINISTIC per
    (tenant, direction) instead of random, so it matches the two accounts the session
    opener seeds — satisfying the new same-tenant FK on ledger_entries. The parent
    (pure-Pydantic D-001) suite is unaffected; this override only applies under
    ``tests/persistence/``. ``make_balanced_txn`` (parent) depends on this fixture and
    so inherits the deterministic accounts.
    """

    def _make(
        *,
        tenant_id: str,
        direction,
        cents: int,
        currency: str = "USD",
        timestamp: datetime | None = None,
        **over: object,
    ) -> LedgerEntry:
        fields: dict[str, object] = {
            "entry_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "account_id": builder_account_id(tenant_id, direction.value),
            "direction": direction,
            "amount": Money(minor_units=cents, currency=currency),
            "team_id": str(uuid.uuid4()),
            "project_id": str(uuid.uuid4()),
            "agent_id": "gateway-core",
            "timestamp": timestamp or _FIXED_NOW,
        }
        fields.update(over)
        return LedgerEntry(**fields)

    return _make


@pytest.fixture
def debit_account_id(tenant_id: str) -> str:
    """The deterministic debit account the session opener seeds for the test's tenant.

    Used by the raw-insert negative tests so their single-leg insert references a real,
    same-tenant account (the FK is then satisfied and the COMMIT-time balance trigger
    is what rejects the write — preserving the original test intent).
    """
    return builder_account_id(tenant_id, "debit")
