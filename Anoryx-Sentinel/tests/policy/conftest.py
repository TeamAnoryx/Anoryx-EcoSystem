"""Fixtures for F-008 policy tests (ADR-0009).

Self-contained (does not depend on tests/persistence/conftest.py):
  * loads the monorepo-root .env (DATABASE_URL etc.);
  * ensure_schema_at_head — `alembic upgrade head` once per session (applies 0008);
  * priv_session — privileged (DATABASE_URL / BYPASSRLS) session with SAVEPOINT
    rollback, so intake's persist + audit writes never pollute sentinel_dev;
  * signing_keypair — a fresh ES256 keypair whose PUBLIC key is written to a tmp
    PEM, with POLICY_SIGNING_PUBKEY_PATH pointed at it and the load-once crypto
    cache reset (so intake verifies against this test key);
  * record factories for the three contract variants.

Intake uses the privileged session for both persist and audit, and asserts the
privileged role + app.session_kind marker — priv_session satisfies both.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
import pytest_asyncio
from dotenv import dotenv_values, load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_SENTINEL_ROOT = Path(__file__).parent.parent.parent
_ENV_FILE = str(_SENTINEL_ROOT.parent / ".env")
load_dotenv(dotenv_path=_ENV_FILE)

if not os.environ.get("DATABASE_URL"):
    pytest.fail(
        "DATABASE_URL is not set. F-008 policy tests need the privileged "
        "connection. Add it to the monorepo-root .env (see .env.example)."
    )

# Placeholder compact-JWS that satisfies the schema pattern + minLength 16 but is
# NOT a real signature. Tests that need a real one call crypto.sign_policy_record.
PLACEHOLDER_SIG = "aaaaaaaa.bbbbbbbb.cccccccc"


def _async_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    return re.sub(r"^postgresql://", "postgresql+asyncpg://", url)


@pytest.fixture(scope="session", autouse=True)
def ensure_schema_at_head() -> None:
    """Run `alembic upgrade head` before any policy test (applies migration 0008)."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SENTINEL_ROOT / "src")
    env.update({k: v for k, v in dotenv_values(_ENV_FILE).items() if v is not None})
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(_SENTINEL_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(f"ensure_schema_at_head: alembic upgrade head failed:\n{result.stderr}")


@pytest_asyncio.fixture(scope="function")
async def priv_session() -> AsyncSession:
    """Privileged session with SAVEPOINT rollback (no DB pollution)."""
    engine = create_async_engine(
        _async_url(os.environ["DATABASE_URL"]),
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False, autocommit=False
    )
    async with factory() as sess:
        async with sess.begin():
            nested = await sess.begin_nested()
            yield sess
            await nested.rollback()
    await engine.dispose()


@pytest.fixture(scope="function")
def signing_keypair(tmp_path, monkeypatch):
    """A fresh ES256 keypair; POLICY_SIGNING_PUBKEY_PATH -> its public PEM.

    Yields the PRIVATE key (tests sign records with it; intake verifies with the
    matching public key). The load-once crypto cache is reset before and after.
    """
    from policy import crypto

    private_key, public_key = crypto.generate_keypair()
    pub_path = tmp_path / "policy_pub.pem"
    pub_path.write_bytes(crypto.public_key_to_pem(public_key))
    monkeypatch.setenv("POLICY_SIGNING_PUBKEY_PATH", str(pub_path))
    crypto.reset_key_cache_for_testing()
    yield private_key
    crypto.reset_key_cache_for_testing()


@pytest_asyncio.fixture(scope="function")
async def seeded_tenant(priv_session) -> str:
    """Insert a tenant into the SAVEPOINT session so a policy FK insert resolves.

    policies.tenant_id has a FK to tenants.tenant_id (RESTRICT). Accept-path tests
    that persist a policy must reference a real tenant. Rolled back with the
    SAVEPOINT, so sentinel_dev is untouched.
    """
    from persistence.models.tenant import Tenant

    tenant_id = str(uuid.uuid4())
    priv_session.add(Tenant(tenant_id=tenant_id, name="f008-test-tenant", is_active=True))
    await priv_session.flush()
    return tenant_id


def _ids() -> dict[str, str]:
    return {
        "tenant_id": str(uuid.uuid4()),
        "team_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "agent_id": "gateway-core",
    }


@pytest.fixture
def make_budget_record():
    def _make(**overrides):
        rec = {
            "policy_type": "budget_limit",
            **_ids(),
            "policy_id": str(uuid.uuid4()),
            "policy_version": 1,
            "effective_from": "2026-06-17T00:00:00Z",
            "signature": PLACEHOLDER_SIG,
            "period": "daily",
            "scope": "tenant",
            "max_tokens_per_period": 100000,
        }
        rec.update(overrides)
        return rec

    return _make


@pytest.fixture
def make_allowlist_record():
    def _make(**overrides):
        rec = {
            "policy_type": "model_allowlist",
            **_ids(),
            "policy_id": str(uuid.uuid4()),
            "policy_version": 1,
            "effective_from": "2026-06-17T00:00:00Z",
            "signature": PLACEHOLDER_SIG,
            "allowed_model_ids": ["gpt-4o", "claude-3-5-sonnet"],
        }
        rec.update(overrides)
        return rec

    return _make


@pytest.fixture
def make_denylist_record():
    def _make(**overrides):
        rec = {
            "policy_type": "model_denylist",
            **_ids(),
            "policy_id": str(uuid.uuid4()),
            "policy_version": 1,
            "effective_from": "2026-06-17T00:00:00Z",
            "signature": PLACEHOLDER_SIG,
            "denied_model_ids": ["gpt-4"],
            "reason": "cost control",
        }
        rec.update(overrides)
        return rec

    return _make
