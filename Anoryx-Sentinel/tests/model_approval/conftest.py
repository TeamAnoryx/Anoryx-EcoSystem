"""DB readiness for the model_approval test package (F-019).

Self-provisioning, mirroring tests/data_lock/conftest.py and tests/code_scan/
conftest.py: this package provisions the schema (alembic upgrade head) + the
sentinel_app password before its DB-gated tests run, so it works on a fresh CI DB
and when run in isolation (memory: a new DB-test package needs its own DB-gated
provisioning, AND its own per-function engine-cache reset or asyncio_mode=auto
yields 'Event loop is closed' / InvalidPassword across packages).

DB-GATED: a no-op when DATABASE_URL/APP_DATABASE_URL are absent or Postgres is
unreachable, so the pure-unit model_approval tests run without a database.

Requires (same as all real-DB tests):
  - DATABASE_URL (superuser) + APP_DATABASE_URL (sentinel_app) in root .env
  - SENTINEL_PROVISION_APP_ROLE=1
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import subprocess
import sys
from typing import AsyncIterator

import pytest
import pytest_asyncio
from dotenv import load_dotenv

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)

_SENTINEL_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _parse_pg(url: str):
    return re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)


@pytest_asyncio.fixture(autouse=True)
async def _reset_db_engine_caches() -> AsyncIterator[None]:
    """Dispose + null persistence.database engine caches after each test.

    asyncio_mode=auto uses a per-function event loop; the module-global app /
    privileged engines are bound to the loop of first use, so a later test in a
    fresh loop would hit 'Event loop is closed' on the stale pool. Resetting the
    caches per test makes each test create engines in its own loop (mirrors
    tests/data_lock/conftest.py + code_scan/bulk/compliance/admin).
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

    # SETUP reset: dispose any engine singleton leaked from a prior package/test
    # (a gateway/orchestration test monkeypatches APP_DATABASE_URL to a fake host
    # and builds the singleton; the env reverts at teardown but the cached engine
    # does NOT — f-019). Reset here so THIS test builds a fresh engine from the
    # current env in its own loop, regardless of what ran before.
    await _dispose()
    yield
    await _dispose()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _ensure_model_approval_db_ready() -> AsyncIterator[None]:
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
        pytest.fail(
            f"_ensure_model_approval_db_ready: alembic upgrade head failed:\n{result.stderr}"
        )

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
