"""F-017 CRIT-2 guard: data_lock IS a persistable policy_type (vectors 5, 6).

This is the STEP-2 countermeasure to the exact failure that made F-016 inert: a
new policy_type that is not registered in _VALID_POLICY_TYPES AND both DB CHECK
constraints (ck_policies_policy_type / ck_pv_policy_type) cannot be written, so
the whole feature is a permanent no-op — and stubbed config tests hide it.

It proves, with ZERO stubs on the persist/load path:

    real upsert_policy('data_lock')  →  committed rows  →  real RLS load

Vector 5: real PolicyRepository.upsert_policy(policy_type='data_lock') writes
          both a policies row and a policy_versions row; a real RLS-scoped
          get_active_policies_for_scope(tenant, 'data_lock') loads it back and
          the payload parses to enabled=True with the declared rules.
Vector 6: both CHECK constraints accept 'data_lock' (the upsert proves it) AND
          still reject an unknown policy_type at the DB layer (constraint live).

DB-GATED: skips gracefully when DATABASE_URL / APP_DATABASE_URL are absent or
Postgres is unreachable (same pattern as tests/code_scan/test_crit2_real_path.py).
SENTINEL_PROVISION_APP_ROLE=1 is required (same as all real-DB tests).
"""

from __future__ import annotations

import base64
import json
import os
import re
import uuid
from datetime import datetime, timezone

import asyncpg
import pytest
import pytest_asyncio
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)

pytestmark = pytest.mark.asyncio


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _make_jws() -> str:
    """Syntactically valid compact-JWS placeholder (same as test_repositories.py)."""
    seg = base64.urlsafe_b64encode(b"x" * 20).decode().rstrip("=")
    return f"{seg}.{seg}.{seg}"


def _privileged_engine(db_url: str):
    return create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


_SKIP_REASON = (
    "DATABASE_URL / APP_DATABASE_URL not set or Postgres unreachable — "
    "skipping real-DB F-017 CRIT-2 persist guard"
)

# The data_lock policy payload shape (ADR-0020 §6). Two rules: one time, one
# permission — both must survive the round-trip intact.
_DATA_LOCK_PAYLOAD = {
    "enabled": True,
    "rules": [
        {
            "field_path": "result.ssn",
            "condition": {"type": "time", "unlock_at": "2030-01-01T00:00:00Z"},
        },
        {
            "field_path": "result.salary",
            "condition": {
                "type": "permission",
                "allow": {"project_id": ["proj-finance"], "team_id": ["team-hr"]},
            },
        },
    ],
}


@pytest_asyncio.fixture()
async def seeded_tenant():
    """Seed a committed tenant (policies.tenant_id FKs tenants) + cleanup handle.

    Only the tenant row is strictly required: on the policies/policy_versions
    tables only tenant_id is a foreign key; team_id/project_id/agent_id are plain
    string columns (server-side cross-check, not FKs). Keeps the fixture minimal.
    """
    db_raw = os.environ.get("DATABASE_URL", "")
    app_raw = os.environ.get("APP_DATABASE_URL", "")
    if not db_raw or not app_raw:
        pytest.skip(_SKIP_REASON)

    m = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", db_raw)
    if not m:
        pytest.skip(_SKIP_REASON)
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
        pytest.skip(_SKIP_REASON)

    db_url = _to_asyncpg_url(db_raw)
    tenant_id = str(uuid.uuid4())
    engine = _privileged_engine(db_url)

    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant_id, "n": f"f017-{tenant_id[:8]}"},
        )
    await engine.dispose()

    async def _cleanup() -> None:
        ce = _privileged_engine(db_url)
        try:
            async with ce.begin() as conn:
                await conn.execute(
                    text("DELETE FROM policy_versions WHERE tenant_id = :t"), {"t": tenant_id}
                )
                await conn.execute(
                    text("DELETE FROM policies WHERE tenant_id = :t"), {"t": tenant_id}
                )
                await conn.execute(
                    text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tenant_id}
                )
        finally:
            await ce.dispose()

    yield {"tenant_id": tenant_id, "db_url": db_url}
    await _cleanup()


async def test_data_lock_policy_persists_and_loads(seeded_tenant) -> None:
    """Vector 5: real upsert('data_lock') → real RLS load → enabled rules intact."""
    from persistence.database import get_tenant_session
    from persistence.repositories.policy_repository import PolicyRepository

    tenant_id = seeded_tenant["tenant_id"]
    team_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    agent_id = "f017-test"
    policy_id = str(uuid.uuid4())

    engine = _privileged_engine(seeded_tenant["db_url"])
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    # Persist through the REAL write path (no stubs). A ValueError here would mean
    # 'data_lock' is missing from _VALID_POLICY_TYPES; a CheckViolationError would
    # mean a constraint was not widened — both are the CRIT-2 failure.
    async with factory() as sess:
        async with sess.begin():
            policy, version = await PolicyRepository(sess).upsert_policy(
                policy_id=policy_id,
                policy_type="data_lock",
                policy_version=1,
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=project_id,
                agent_id=agent_id,
                effective_from=datetime.now(timezone.utc),
                signature=_make_jws(),
                policy_payload=_DATA_LOCK_PAYLOAD,
            )
    assert policy.policy_type == "data_lock"
    assert version.policy_type == "data_lock"
    await engine.dispose()

    # Load back through the REAL RLS-scoped session (production load path).
    async with get_tenant_session(tenant_id) as session:
        rows = await PolicyRepository(session).get_active_policies_for_scope(tenant_id, "data_lock")
    assert len(rows) == 1, "data_lock policy did not load back — feature would be inert"
    loaded = json.loads(rows[0].policy_payload)
    assert loaded["enabled"] is True
    assert len(loaded["rules"]) == 2
    assert loaded["rules"][0]["condition"]["type"] == "time"
    assert loaded["rules"][1]["condition"]["type"] == "permission"


async def test_unknown_policy_type_still_rejected_by_db(seeded_tenant) -> None:
    """Vector 6: widening did not loosen the gate — an unknown type is still rejected.

    Direct privileged INSERT bypasses the app-layer _VALID_POLICY_TYPES check, so
    this exercises the DB CHECK constraint (ck_policies_policy_type) itself.
    """
    import sqlalchemy.exc

    tenant_id = seeded_tenant["tenant_id"]
    engine = _privileged_engine(seeded_tenant["db_url"])
    # SQLAlchemy's asyncpg dialect wraps the raw asyncpg.CheckViolationError as
    # sqlalchemy.exc.IntegrityError; assert on the wrapper (the .orig is the
    # asyncpg CheckViolationError against ck_policies_policy_type).
    with pytest.raises(sqlalchemy.exc.IntegrityError):
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO policies (policy_id, policy_type, tenant_id, team_id, "
                    "project_id, agent_id, current_version, effective_from, signature, "
                    "policy_payload, created_at, updated_at) VALUES "
                    "(:pid, 'not_a_real_type', :t, :tm, :p, :a, 1, now(), :sig, '{}', "
                    "now(), now())"
                ),
                {
                    "pid": str(uuid.uuid4()),
                    "t": tenant_id,
                    "tm": str(uuid.uuid4()),
                    "p": str(uuid.uuid4()),
                    "a": "x",
                    "sig": _make_jws(),
                },
            )
    await engine.dispose()
