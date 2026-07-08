"""Fixtures for the D-011 forecasting DB suite. Mirrors tests/budget_engine/conftest.py
(budget creation, tenant-scoped sessions) + tests/dashboards/conftest.py (real usage
seeding via the D-004 posting path, the admin app/client for the router e2e) — this
suite needs both a budget to forecast against AND ledger rows to forecast from.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope
from delta.budget_engine.definitions import create_budget

_DELTA_ROOT = Path(__file__).resolve().parents[2]  # .../Delta
_DEFAULT_TEST_TOKEN = "test-admin-token-do-not-use-in-prod"  # noqa: S105


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


def _db_env_present() -> bool:
    return bool(os.environ.get("DATABASE_URL") and os.environ.get("APP_DATABASE_URL"))


db_required = pytest.mark.skipif(
    not _db_env_present(), reason="DATABASE_URL/APP_DATABASE_URL unset (no live Postgres)"
)


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
                    "TRUNCATE delta.budget_definitions, delta.ledger_entries, "
                    "delta.transactions, delta.accounts, delta.ingest_dead_letter CASCADE"
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


@pytest.fixture
def tenant_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def other_tenant_id() -> str:
    return str(uuid.uuid4())


def _factory(engine) -> async_sessionmaker:
    return async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False, autocommit=False
    )


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


@pytest.fixture
def make_budget() -> Callable[..., Awaitable[object]]:
    """Create a budget (real INSERT via delta.budget_engine.definitions.create_budget)."""

    async def _make(
        *,
        tenant_id: str,
        cap_cents: int | None,
        scope: BudgetScope = BudgetScope.TENANT,
        team_id: str | None = None,
        project_id: str | None = None,
        agent_id: str = "gateway-core",
        period: BudgetPeriod = BudgetPeriod.MONTHLY,
        limit_tokens: int | None = None,
    ):
        # BudgetConcept requires at least one of limit_tokens/limit_cost_cents — a "no
        # cost cap" test needs a token-only budget, not a genuinely limit-less one.
        if cap_cents is None and limit_tokens is None:
            limit_tokens = 1_000_000
        concept = BudgetConcept(
            tenant_id=tenant_id,
            team_id=team_id or str(uuid.uuid4()),
            project_id=project_id or str(uuid.uuid4()),
            agent_id=agent_id,
            scope=scope,
            period=period,
            limit_cost_cents=cap_cents,
            limit_tokens=limit_tokens,
        )
        async with open_tenant_session(tenant_id) as s:
            bd = await create_budget(s, concept, now=datetime.now(timezone.utc))
            await s.commit()
        return bd

    return _make


@pytest.fixture
def seed_usage() -> Callable[..., Awaitable[None]]:
    """Post a real usage event through the real D-004 path (never a hand-inserted row)."""

    async def _seed(
        *,
        tenant_id: str,
        team_id: str | None = None,
        project_id: str | None = None,
        agent_id: str = "gateway-core",
        cost_cents: int = 1000,
        timestamp: str,
        event_id: str | None = None,
    ) -> None:
        from delta.ingest.posting import build_usage_record, post_usage

        payload = {
            "event_type": "usage",
            "tenant_id": tenant_id,
            "team_id": team_id or str(uuid.uuid4()),
            "project_id": project_id or str(uuid.uuid4()),
            "agent_id": agent_id,
            "event_id": event_id or str(uuid.uuid4()),
            "event_timestamp": timestamp,
            "request_id": "req-" + uuid.uuid4().hex[:24],
            "model": "gpt-4o",
            "tokens_in": 10,
            "tokens_out": 20,
            "latency_ms": 5,
            "cost_estimate_cents": cost_cents,
        }
        record = build_usage_record(payload)
        await post_usage(record)

    return _seed


# --------------------------------------------------------------------------- admin app/client
@pytest.fixture(scope="session", autouse=True)
def admin_token() -> str:
    raw = os.environ.get("DELTA_ADMIN_TOKEN")
    if not raw:
        raw = _DEFAULT_TEST_TOKEN
        os.environ["DELTA_ADMIN_TOKEN"] = raw
    return raw


@pytest.fixture
def app(admin_token: str):
    from delta.allocation_admin.app import create_app

    return create_app()


@pytest_asyncio.fixture
async def client(app) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://delta") as c:
        yield c


@pytest.fixture
def auth_headers(admin_token: str) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}
