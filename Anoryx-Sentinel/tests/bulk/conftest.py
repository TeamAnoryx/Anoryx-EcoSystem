"""Bulk test fixtures (F-015, ADR-0018).

Self-provisioning DB readiness mirrors tests/admin/conftest.py (the F-011/F-012a
CI lesson): test packages run alphabetically, so tests/bulk/ runs BEFORE
tests/persistence/ — a fresh CI DB would have neither schema nor a provisioned
sentinel_app when the bulk DB tests run. This package provisions itself and is
DB-GATED: with no DATABASE_URL/APP_DATABASE_URL (or Postgres unreachable) it is a
no-op so the pure-unit storage/key/content tests still run.

DB-backed bulk tests require live Postgres (DATABASE_URL + APP_DATABASE_URL) and
SENTINEL_PROVISION_APP_ROLE=1.
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

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)

_SENTINEL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _parse_pg(url: str):
    return re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)


@pytest.fixture(autouse=True)
def _pin_gateway_list_env(monkeypatch):
    """Pin list-typed settings to valid JSON so get_settings() parses (root .env
    carries non-JSON values; the admin fixture pins them the same way)."""
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "[]")
    monkeypatch.setenv("ROUTER_DEFAULT_PROVIDERS", '["openai"]')
    from gateway.config import _reset_settings

    _reset_settings()
    yield
    _reset_settings()


@pytest.fixture()
def test_tenant_id() -> str:
    """Tenant-A id (UUID v4)."""
    return str(uuid.uuid4())


@pytest.fixture()
def tenant_b_id() -> str:
    """Tenant-B id for cross-tenant isolation proofs (UUID v4)."""
    return str(uuid.uuid4())


@pytest.fixture()
def db_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        pytest.skip("DATABASE_URL not set — skipping DB-backed bulk test")
    return _to_asyncpg_url(raw)


@pytest.fixture()
def app_db_url() -> str:
    raw = os.environ.get("APP_DATABASE_URL", "")
    if not raw:
        pytest.skip("APP_DATABASE_URL not set — skipping DB-backed bulk test")
    return _to_asyncpg_url(raw)


def _privileged_engine(db_url: str):
    return create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


@pytest_asyncio.fixture()
async def seed_tenants(db_url: str):
    """Factory: commit a `tenants` registry row (privileged) so FK + RLS work.

    Bulk state rows FK to tenants.tenant_id (RESTRICT); the row must be COMMITTED
    so the sentinel_app tenant session (separate connection) sees it. Seeded rows
    + any batch rows are removed by the `cleanup_bulk_after` teardown.
    """
    engine = _privileged_engine(db_url)
    seeded: list[str] = []

    async def _seed(*tenant_ids: str) -> None:
        async with engine.begin() as conn:
            for tid in tenant_ids:
                await conn.execute(
                    text(
                        "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                        "VALUES (:tid, :name, :name, true) ON CONFLICT (tenant_id) DO NOTHING"
                    ),
                    {"tid": tid, "name": f"bulk-test-{tid[:8]}"},
                )
                seeded.append(tid)

    yield _seed
    await engine.dispose()


def _tenant_engine(app_db_url: str):
    return create_async_engine(app_db_url, pool_pre_ping=True, echo=False)


@pytest_asyncio.fixture()
async def tenant_session_factory(app_db_url: str):
    """Factory yielding a COMMITTING RLS-scoped session for a given tenant.

    Unlike the no-commit nested-rollback pattern, bulk cross-tenant proofs need
    real committed rows over a real sentinel_app (NOBYPASSRLS) connection, so a
    second tenant's session genuinely cannot see them. Cleanup is done by
    `cleanup_bulk_after`.
    """
    engines = []

    def _make(tenant_id: str):
        engine = _tenant_engine(app_db_url)
        engines.append(engine)
        factory = async_sessionmaker(
            bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
        )

        def _session():
            # Returns an async context manager that sets the GUC then yields a session.
            return _ScopedTenantSession(factory, tenant_id)

        return _session

    yield _make
    for e in engines:
        await e.dispose()


class _ScopedTenantSession:
    """Async CM: open a sentinel_app session with the tenant GUC set; commit on exit."""

    def __init__(self, factory, tenant_id: str) -> None:
        self._factory = factory
        self._tenant_id = tenant_id
        self._sess: AsyncSession | None = None

    async def __aenter__(self) -> AsyncSession:
        self._sess = self._factory()
        await self._sess.__aenter__()
        await self._sess.begin()
        await self._sess.execute(
            text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": self._tenant_id},
        )
        return self._sess

    async def __aexit__(self, exc_type, exc, tb) -> None:
        assert self._sess is not None
        try:
            if exc_type is None:
                await self._sess.commit()
            else:
                await self._sess.rollback()
        finally:
            await self._sess.__aexit__(exc_type, exc, tb)


@pytest_asyncio.fixture()
async def cleanup_bulk_after(db_url: str) -> AsyncIterator[None]:
    """Yield, then remove all bulk + audit rows (privileged) in teardown.

    batch_files/batches have no append-only trigger (plain DELETE works);
    events_audit_log has a BEFORE DELETE trigger so it is TRUNCATEd (bypasses the
    trigger — local dev/CI only). Tenants seeded by tests are left (harmless) or
    removed last.
    """
    yield
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        return
    engine = _privileged_engine(_to_asyncpg_url(raw))
    try:
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM batch_files"))
            await conn.execute(text("DELETE FROM batches"))
            await conn.execute(text("TRUNCATE events_audit_log"))
    finally:
        await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def _reset_db_engine_caches() -> AsyncIterator[None]:
    """Dispose persistence.database engine caches after each test (per-fn loop)."""
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
            except Exception:
                pass
        setattr(_db, _engine_attr, None)
        setattr(_db, _factory_attr, None)


# ---------------------------------------------------------------------------
# Redis pool + stub storage + batch seeder (worker/limit tests)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def redis_pool() -> AsyncIterator[None]:
    """Init the shared Redis pool for the test, then flush bulk keys + shut down.

    Skips when REDIS is unreachable so DB-only worker tests still run.
    """
    import gateway.redis_client as rc
    from gateway.config import _reset_settings, get_settings

    _reset_settings()
    settings = get_settings()
    await rc.init(settings)
    if rc.is_degraded():
        await rc.shutdown()
        rc._reset_for_testing()
        pytest.skip("Redis unreachable — skipping Redis-backed bulk test")
    try:
        yield
    finally:
        # Flush only F-015 keys (stream, dlq, limit counters) for test isolation.
        try:
            async with await rc.get_client() as client:
                keys = await client.keys("sentinel:bulk:*")
                if keys:
                    await client.delete(*keys)
        except Exception:
            pass
        await rc.shutdown()
        rc._reset_for_testing()


class StubStorage:
    """In-memory Storage stub: fetch returns preset bytes; specific keys can fail."""

    def __init__(self) -> None:
        self.content: dict[str, bytes] = {}
        self.fail_keys: dict[str, Exception] = {}

    def presign_upload(self, key, *, max_bytes, ttl):  # pragma: no cover - unused in worker tests
        raise NotImplementedError

    def presign_download(self, key, *, ttl):  # pragma: no cover
        raise NotImplementedError

    async def fetch(self, key: str, *, max_bytes: int) -> bytes:
        if key in self.fail_keys:
            raise self.fail_keys[key]
        return self.content.get(key, b"")

    async def head(self, key):  # pragma: no cover
        raise NotImplementedError

    async def delete(self, key):  # pragma: no cover
        return None


@pytest.fixture()
def stub_storage() -> StubStorage:
    return StubStorage()


@pytest_asyncio.fixture()
async def seed_batch(seed_tenants, tenant_session_factory):
    """Factory: seed a committed batch + files. Returns (batch_id, [(file_id, key)])."""
    from bulk.repositories.batch_repository import BatchRepository
    from bulk.storage.keys import mint_object_key

    async def _seed(
        tenant_id: str,
        *,
        object_count: int = 1,
        model: str | None = None,
        idempotency_key: str = "seed-K",
    ):
        await seed_tenants(tenant_id)
        make = tenant_session_factory(tenant_id)
        group = str(uuid.uuid4())
        keys = [mint_object_key(tenant_id, group) for _ in range(object_count)]
        async with make() as s:
            repo = BatchRepository(s)
            batch, files = await repo.create_batch(
                tenant_id=tenant_id,
                team_id=str(uuid.uuid4()),
                project_id=str(uuid.uuid4()),
                agent_id="bulk-test",
                idempotency_key=idempotency_key,
                object_keys=keys,
                model=model,
            )
            return batch.batch_id, [(f.file_id, f.object_key) for f in files]

    return _seed


@pytest_asyncio.fixture()
def bulk_app():
    """Real gateway app (mounts the bulk router). list-typed settings are pinned by
    the autouse _pin_gateway_list_env fixture. Skips when no DB configured."""
    if not os.environ.get("DATABASE_URL") or not os.environ.get("APP_DATABASE_URL"):
        pytest.skip("DATABASE_URL/APP_DATABASE_URL not set — skipping app-backed bulk test")
    from gateway.config import _reset_settings
    from gateway.main import create_app

    _reset_settings()
    return create_app()


@pytest_asyncio.fixture()
async def seeded_key(db_url: str):
    """Seed a tenants row + a virtual API key (known plaintext) via the privileged
    engine. Returns dict with plaintext + the four IDs + ready-to-use auth headers."""
    import secrets as _secrets

    from sqlalchemy.ext.asyncio import async_sessionmaker

    from persistence.repositories.virtual_api_key_repository import VirtualApiKeyRepository

    tenant_id = str(uuid.uuid4())
    team_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    agent_id = "bulk-test"
    plaintext = "sk-bulk-" + _secrets.token_urlsafe(24)

    engine = _privileged_engine(db_url)
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant_id, "n": f"key-{tenant_id[:8]}"},
        )
        # virtual_api_keys FKs team_id -> teams and project_id -> projects (RESTRICT).
        await conn.execute(
            text(
                "INSERT INTO teams (team_id, tenant_id, name, is_active) "
                "VALUES (:tm, :t, :n, true) ON CONFLICT (team_id) DO NOTHING"
            ),
            {"tm": team_id, "t": tenant_id, "n": f"team-{team_id[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO projects (project_id, team_id, tenant_id, name, is_active) "
                "VALUES (:p, :tm, :t, :n, true) ON CONFLICT (project_id) DO NOTHING"
            ),
            {"p": project_id, "tm": team_id, "t": tenant_id, "n": f"proj-{project_id[:8]}"},
        )
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        async with s.begin():
            await VirtualApiKeyRepository(s).create(
                plaintext,
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=project_id,
                agent_id=agent_id,
                label="bulk-test",
            )
    await engine.dispose()

    return {
        "plaintext": plaintext,
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": agent_id,
        "headers": {
            "Authorization": f"Bearer {plaintext}",
            "X-Anoryx-Tenant-Id": tenant_id,
            "X-Anoryx-Team-Id": team_id,
            "X-Anoryx-Project-Id": project_id,
            "X-Anoryx-Agent-Id": agent_id,
        },
    }


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _ensure_bulk_db_ready() -> AsyncIterator[None]:
    db_url = os.environ.get("DATABASE_URL", "")
    app_url = os.environ.get("APP_DATABASE_URL", "")
    if not db_url or not app_url:
        yield
        return

    m = _parse_pg(db_url)
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
        yield
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
        timeout=90,
    )
    if result.returncode != 0:
        pytest.fail(f"_ensure_bulk_db_ready: alembic upgrade head failed:\n{result.stderr}")

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
