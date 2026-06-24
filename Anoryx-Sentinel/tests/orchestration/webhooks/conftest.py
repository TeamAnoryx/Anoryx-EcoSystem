"""DB/Redis-readiness conftest for tests/orchestration/webhooks/ (F-020).

Self-provisioning, mirroring data_lock/conftest.py and code_scan/conftest.py:
this package provisions the schema (alembic upgrade head) + sentinel_app password
before its DB-gated tests run, so it works on a fresh CI DB and when run in
isolation.

HARNESS RULES (battle-tested):
- New DB-test package must own its per-function _reset_db_engine_caches() autouse
  fixture; otherwise 'Event loop is closed' / asyncpg InvalidPassword on the second
  test in the package.
- session-scoped _ensure_webhooks_db_ready provisions schema + role once per
  session; reachability probe skips cleanly when Postgres is unreachable.
- Redis-gated tests check REDIS_URL at skip-time.

DB-GATED: no-op when DATABASE_URL/APP_DATABASE_URL absent or Postgres unreachable.
Redis-gated: tests guard themselves via a skip on missing REDIS_URL.
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

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)

_SENTINEL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def _parse_pg(url: str):
    return re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


# ---------------------------------------------------------------------------
# Synthetic test IDs — purely synthetic UUIDs, no real PII.
# ---------------------------------------------------------------------------

TEST_TENANT_A_ID = str(uuid.uuid4())
TEST_TENANT_B_ID = str(uuid.uuid4())
TEST_TEAM_ID = str(uuid.uuid4())
TEST_PROJECT_ID = str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Per-function engine cache reset (battle-tested pattern — see data_lock)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(autouse=True)
async def _reset_db_engine_caches() -> AsyncIterator[None]:
    """Dispose + null persistence.database engine singletons before/after each test.

    asyncio_mode=auto uses a per-function event loop; the module-global app /
    privileged engines are bound to the loop of first use. Reset here so each test
    creates engines in its own loop.  Mirrors data_lock/conftest.py.
    """

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

    await _dispose()
    yield
    await _dispose()


# ---------------------------------------------------------------------------
# Session-autouse: provision schema + sentinel_app before any DB test.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _ensure_webhooks_db_ready() -> AsyncIterator[None]:
    """Session-autouse: alembic upgrade head + sentinel_app SCRAM verifier.

    No-op (yields immediately) when Postgres is absent or unreachable, so
    pure-unit tests in this package still run.
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
        pytest.fail(f"_ensure_webhooks_db_ready: alembic upgrade head failed:\n{result.stderr}")

    # 2) Provision sentinel_app SCRAM verifier (plaintext never in SQL).
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
# Shared SENTINEL_IDP_SECRET_KEY fixture (runtime-assembled, never hardcoded).
# Mirrors the F-014/F-017/F-019 pattern: os.urandom(32) → base64.
# ---------------------------------------------------------------------------


@pytest.fixture()
def idp_secret_key_env(monkeypatch) -> str:
    """Set SENTINEL_IDP_SECRET_KEY to a fresh random key for the test.

    Returns the base64-encoded key string. The key is NEVER stored or logged.
    """
    import base64 as _b64

    raw_key = os.urandom(32)
    key_b64 = _b64.b64encode(raw_key).decode()
    monkeypatch.setenv("SENTINEL_IDP_SECRET_KEY", key_b64)
    # Reset the secret_box key cache so it picks up the fresh key.
    from admin.sso import secret_box as _sb

    _sb.reset_key_cache_for_testing()
    yield key_b64
    _sb.reset_key_cache_for_testing()


# ---------------------------------------------------------------------------
# Webhook settings reset fixture (clears lru_cache between tests).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_webhook_settings() -> None:
    """Clear the webhook settings lru_cache before/after each test so env
    monkeypatching in tests takes effect cleanly.
    """
    from orchestration.webhooks.config import _reset_webhook_settings_for_testing

    _reset_webhook_settings_for_testing()
    yield
    _reset_webhook_settings_for_testing()
