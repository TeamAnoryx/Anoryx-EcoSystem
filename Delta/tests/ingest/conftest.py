"""Fixtures for the Delta event-ingest suite (D-004).

Self-contained DB harness that MIRRORS ``tests/persistence/conftest.py`` (the D-003
proven pattern): ``alembic upgrade head`` once per session, per-test SCRAM provisioning
of ``delta_app``, and a privileged TRUNCATE before each test on an append-only ledger
(every test also uses a fresh random tenant, so committed rows never collide and RLS
keeps each test's view to its own tenant).

DIFFERENCE FROM persistence/conftest (deliberate): the DB-touching autouse fixtures here
NO-OP when ``DATABASE_URL`` / ``APP_DATABASE_URL`` are unset, instead of ``pytest.fail``.
The DB-backed modules (``test_ingest_db``, ``test_seam_e2e``) carry their OWN module-level
``skipif`` on the env, so the pure-unit modules (hmac / validation / errors) still run with
no Postgres. The production ``delta.persistence.database`` engine singletons are reset
around every test (asyncio_mode=auto → per-function loop) so the REAL app request path
(``get_tenant_session``) rebuilds its engine in the current loop.

No secret, URL, or credential is ever logged. The HMAC secret used to sign requests is a
test-only value (never a real secret).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import subprocess
import sys
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from delta.ingest.app import create_app

_DELTA_ROOT = Path(__file__).resolve().parents[2]  # .../Delta

# A deterministic, test-only HMAC secret (never a real credential). Set into the env when
# DELTA_INGEST_HMAC_SECRET is unset so create_app() and the dispatcher signer agree.
_DEFAULT_TEST_SECRET = "delta-ingest-test-secret"  # noqa: S105 - test-only fake


# --------------------------------------------------------------------------- helpers
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
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )


def _db_env_present() -> bool:
    return bool(os.environ.get("DATABASE_URL") and os.environ.get("APP_DATABASE_URL"))


# --------------------------------------------------------------------------- schema/provision
@pytest.fixture(scope="session", autouse=True)
def ensure_schema_at_head() -> None:
    """Run ``alembic upgrade head`` once before any DB-backed ingest test.

    No-op when DATABASE_URL is unset so the pure-unit modules run with no Postgres.
    """
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
    """Re-provision delta_app's password before each DB test (idempotent, cheap).

    Gated by DELTA_PROVISION_APP_ROLE; no-op (and no DB touch) when unset.
    """
    if os.environ.get("DELTA_PROVISION_APP_ROLE", "").lower() not in ("1", "true", "yes", "on"):
        return
    if not _db_env_present():
        return
    await _provision_delta_app(os.environ["DATABASE_URL"], os.environ["APP_DATABASE_URL"])


@pytest_asyncio.fixture(autouse=True)
async def _truncate(provision_app_role: None) -> AsyncIterator[None]:
    """Reset the ingest + ledger tables before each test (privileged TRUNCATE).

    delta_app has no TRUNCATE grant, so only the owner role can do this. No-op when the DB
    env is absent (pure-unit run).
    """
    if not _db_env_present():
        yield
        return
    engine = create_async_engine(_asyncpg(os.environ["DATABASE_URL"]), poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "TRUNCATE delta.ledger_entries, delta.transactions, delta.accounts, "
                    "delta.ingest_dead_letter CASCADE"
                )
            )
    finally:
        await engine.dispose()
    yield


@pytest.fixture(autouse=True)
def _reset_delta_engines() -> Iterator[None]:
    """Reset the production engine singletons around each test.

    asyncio_mode=auto uses a per-function loop; the module-global engines bind to the loop
    of first use, so the REAL app request path (get_tenant_session) must rebuild its engine
    in the current loop. Sync (just nulls the globals) — safe for unit tests too.
    """
    from delta.persistence import database as _db

    _db.reset_engines()
    yield
    _db.reset_engines()


# --------------------------------------------------------------------------- secret + app
@pytest.fixture(scope="session", autouse=True)
def hmac_secret() -> bytes:
    """The shared HMAC secret bytes; sets DELTA_INGEST_HMAC_SECRET if unset (test value)."""
    raw = os.environ.get("DELTA_INGEST_HMAC_SECRET")
    if not raw:
        raw = _DEFAULT_TEST_SECRET
        os.environ["DELTA_INGEST_HMAC_SECRET"] = raw
    return raw.encode("utf-8")


@pytest.fixture
def app(hmac_secret: bytes, monkeypatch: pytest.MonkeyPatch):
    """The real Delta ingest app (POST /v1/ingest/usage + /health).

    These tests exercise ONLY the D-004 consume/posting/DLQ path — never the D-005
    enforcement seam (that is covered by tests/budget_engine with the engine enabled). The
    budget engine defaults to enabled and, when enabled, requires an O-004 distribution URL
    at construction (fail-loud; budget_engine.config). So when no O-004 target is configured
    (the normal ingest-lane env — see delta-ci.yml) set the engine inert here so create_app()
    builds without a distribution URL it does not need; evaluate_after_post is then a no-op.
    If a URL IS configured, the engine is left enabled. This sets only the TEST environment
    (monkeypatch, auto-reverted, scoped to this fixture) — the production fail-loud guard in
    budget_engine.config is unchanged.
    """
    if not os.environ.get("DELTA_ORCH_DISTRIBUTION_URL"):
        monkeypatch.setenv("DELTA_BUDGET_ENGINE_ENABLED", "0")
    return create_app()


@pytest_asyncio.fixture
async def client(app) -> AsyncIterator[httpx.AsyncClient]:
    """An async httpx client bound to the real Delta app via ASGI.

    raise_app_exceptions=False so the app's fail-safe 503 (sent by the catch-all handler)
    is returned to the test as a response, exactly as a real HTTP server would.
    """
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://delta") as c:
        yield c


# --------------------------------------------------------------------------- signing
SignFn = Callable[..., dict[str, str]]


@pytest.fixture
def sign(hmac_secret: bytes) -> SignFn:
    """Return a signer producing the Orchestrator->Delta HMAC headers for ``body``.

    Signature == hmac_sha256(secret, f"{ts}".encode("ascii") + b"." + body).hexdigest().
    The caller MUST transmit exactly ``body`` (the bytes signed here). ``secret`` defaults
    to the bound test secret; pass an override (e.g. a wrong secret) to forge a request.
    """

    def _sign(body: bytes, secret: bytes | None = None, ts: int | None = None) -> dict[str, str]:
        used = hmac_secret if secret is None else secret
        stamp = int(time.time()) if ts is None else int(ts)
        signed = f"{stamp}".encode("ascii") + b"." + body
        digest = hmac.new(used, signed, hashlib.sha256).hexdigest()
        return {
            "X-Orchestrator-Timestamp": str(stamp),
            "X-Orchestrator-Signature": f"sha256={digest}",
            "Content-Type": "application/json",
        }

    return _sign


# --------------------------------------------------------------------------- tenants + event
@pytest.fixture
def tenant_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def other_tenant_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def usage_event() -> Callable[..., dict]:
    """Factory: a valid Sentinel ``UsageEvent`` dict (events.schema.json UsageEvent).

    Canonical dashed UUIDs for tenant/team/project/event; agent_id a lowercase slug;
    event_timestamp an RFC3339 UTC string; request_id in the log-injection-safe charset.
    ``cost`` populates cost_estimate_cents (a JSON number); ``**over`` overrides any field.
    """

    def _make(tenant_id: str, *, event_id: str | None = None, cost: object = 1234, **over) -> dict:
        payload: dict[str, object] = {
            "event_type": "usage",
            "tenant_id": tenant_id,
            "team_id": str(uuid.uuid4()),
            "project_id": str(uuid.uuid4()),
            "agent_id": "gateway-core",
            "event_id": event_id or str(uuid.uuid4()),
            "event_timestamp": "2026-06-26T12:00:00Z",
            "request_id": "req-" + uuid.uuid4().hex[:24],
            "model": "gpt-4o",
            "tokens_in": 100,
            "tokens_out": 200,
            "latency_ms": 42,
            "cost_estimate_cents": cost,
        }
        payload.update(over)
        return payload

    return _make


# --------------------------------------------------------------------------- ledger / DLQ readers
async def _ledger_snapshot(tenant_id: str) -> dict:
    """Counts + debit/credit totals for ``tenant_id`` via a delta_app (RLS) session."""
    engine = create_async_engine(_asyncpg(os.environ["APP_DATABASE_URL"]), poolclass=NullPool)
    try:
        async with _factory(engine)() as s:
            await s.execute(
                text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": tenant_id}
            )
            txns = (await s.execute(text("SELECT count(*) FROM delta.transactions"))).scalar_one()
            entries = (
                await s.execute(text("SELECT count(*) FROM delta.ledger_entries"))
            ).scalar_one()
            debit = (
                await s.execute(
                    text(
                        "SELECT COALESCE(SUM(amount_minor_units), 0) FROM delta.ledger_entries "
                        "WHERE direction = 'debit'"
                    )
                )
            ).scalar_one()
            credit = (
                await s.execute(
                    text(
                        "SELECT COALESCE(SUM(amount_minor_units), 0) FROM delta.ledger_entries "
                        "WHERE direction = 'credit'"
                    )
                )
            ).scalar_one()
            return {
                "txns": int(txns),
                "entries": int(entries),
                "debit": int(debit),
                "credit": int(credit),
                "balanced": int(debit) == int(credit),
            }
    finally:
        await engine.dispose()


async def _dlq_tenant(tenant_id: str, source_event_id: str | None = None) -> list[dict]:
    """DLQ rows visible to ``tenant_id`` (delta_app / RLS), optionally one source_event_id."""
    engine = create_async_engine(_asyncpg(os.environ["APP_DATABASE_URL"]), poolclass=NullPool)
    try:
        async with _factory(engine)() as s:
            await s.execute(
                text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": tenant_id}
            )
            return await _select_dlq(s, source_event_id)
    finally:
        await engine.dispose()


async def _dlq_privileged(source_event_id: str | None = None) -> list[dict]:
    """DLQ rows via the privileged (BYPASSRLS) role — sees NULL-tenant rows too."""
    engine = create_async_engine(_asyncpg(os.environ["DATABASE_URL"]), poolclass=NullPool)
    try:
        async with _factory(engine)() as s:
            return await _select_dlq(s, source_event_id)
    finally:
        await engine.dispose()


async def _select_dlq(session: AsyncSession, source_event_id: str | None) -> list[dict]:
    query = (
        "SELECT dlq_id, tenant_id, source_event_id, event_type, reason "
        "FROM delta.ingest_dead_letter"
    )
    params: dict[str, object] = {}
    if source_event_id is not None:
        query += " WHERE source_event_id = :sid"
        params["sid"] = source_event_id
    rows = (await session.execute(text(query), params)).mappings().all()
    return [dict(r) for r in rows]


@pytest.fixture
def read_tenant_ledger() -> Callable[[str], Awaitable[dict]]:
    """Async reader: ``await read_tenant_ledger(tenant_id)`` -> counts/totals snapshot."""
    return _ledger_snapshot


@pytest.fixture
def read_dlq_tenant() -> Callable[..., Awaitable[list[dict]]]:
    """Async reader: DLQ rows visible to a tenant (RLS-scoped)."""
    return _dlq_tenant


@pytest.fixture
def read_dlq_privileged() -> Callable[..., Awaitable[list[dict]]]:
    """Async reader: DLQ rows via the privileged role (sees NULL-tenant rows)."""
    return _dlq_privileged
