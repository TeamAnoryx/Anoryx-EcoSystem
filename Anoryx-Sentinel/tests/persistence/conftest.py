"""Shared fixtures for persistence tests (F-003).

Connects to the live sentinel-postgres container at localhost:5432.
DATABASE_URL and SENTINEL_KEY_SECRET are loaded from the root .env file.

Required environment variables (see tests/README.md):
  DATABASE_URL          — PostgreSQL connection string.
  SENTINEL_KEY_SECRET   — HMAC secret for virtual API key fingerprinting.

If either is absent, tests fail immediately with a clear error (no silent
fallback injection — pytest.fail() stops the session before wasting time on
database operations that would produce confusing errors).

Session isolation strategy:
- Each test function gets its own AsyncSession with a nested SAVEPOINT.
- The outer transaction is started and rolled back after the test, leaving
  the DB clean for the next test.
- Engine and session_factory are function-scoped to avoid event-loop conflicts
  with pytest-asyncio on Windows (ProactorEventLoop is per-test by default).

Schema guarantee:
- The session-scoped `ensure_schema_at_head` autouse fixture runs alembic
  upgrade head once per test session before any test uses the DB. This
  ensures the schema is present even if a previous run left it downgraded.

NOTE (test hygiene, item 17): the outer transaction in the session fixture is
not committed — changes are visible within the transaction (via SAVEPOINT) but
are rolled back on teardown.  This means tests that depend on committed data
(e.g. the tamper tests in test_audit_chain.py) must manage their own
connections outside this fixture.  This is a known trade-off; a future
improvement would use explicit transaction-per-test commit + cleanup.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Load .env from the monorepo root (three levels up from this conftest).
_env_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_env_path)

# SENTINEL_KEY_SECRET must be set. Fail loudly if absent — no silent injection.
# The variable name is SENTINEL_KEY_SECRET (matches virtual_api_key_repository.py).
# Do NOT use a different name (e.g. SENTINEL_HMAC_SECRET) — keep consistent.
if not os.environ.get("SENTINEL_KEY_SECRET"):
    pytest.fail(
        "SENTINEL_KEY_SECRET environment variable is not set. "
        "Add it to your .env file or export it before running tests. "
        "See tests/README.md for the full list of required test environment variables."
    )


def _make_async_url(raw_url: str) -> str:
    """Convert DATABASE_URL to asyncpg-compatible URL."""
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw_url)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


_SENTINEL_ROOT = Path(__file__).parent.parent.parent
_ENV_FILE = str(_SENTINEL_ROOT.parent / ".env")


@pytest.fixture(scope="session", autouse=True)
def ensure_schema_at_head() -> None:
    """Autouse session fixture: run alembic upgrade head before any tests.

    This guarantees the schema is present even if a previous test run left
    the DB in a downgraded state (e.g., after test_incremental_downgrade).
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SENTINEL_ROOT / "src")
    from dotenv import dotenv_values

    vals = dotenv_values(_ENV_FILE)
    env.update({k: v for k, v in vals.items() if v is not None})

    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(_SENTINEL_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(
            f"ensure_schema_at_head: alembic upgrade head failed:\n{result.stderr}"
        )


@pytest.fixture(scope="function")
def db_url() -> str:
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        pytest.fail("DATABASE_URL is not set. Cannot run persistence tests.")
    return _make_async_url(raw)


@pytest_asyncio.fixture(scope="function")
async def session(db_url: str) -> AsyncSession:
    """Per-test async session with automatic rollback isolation.

    Creates a new engine + session per test function to avoid event-loop
    conflicts with pytest-asyncio on Windows. Uses a nested transaction
    (SAVEPOINT) so each test starts with a clean visible state without
    committing anything to the DB.
    """
    engine = create_async_engine(db_url, pool_pre_ping=True, echo=False)
    factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    async with factory() as sess:
        async with sess.begin():
            nested = await sess.begin_nested()
            yield sess
            await nested.rollback()
    await engine.dispose()
