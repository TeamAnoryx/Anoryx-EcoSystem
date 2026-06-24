"""F-019 CRIT-2 guard: model_approval IS a persistable policy_type (vector 9).

This is the STEP-2 countermeasure to the exact failure that made F-016 inert: a
new policy_type not registered in _VALID_POLICY_TYPES AND both DB CHECK constraints
(ck_policies_policy_type / ck_pv_policy_type) cannot be written, so the whole
default-deny enforcement feature would be a permanent production no-op — and here
that is a SECURITY HOLE (an enforcement layer that silently allows), not merely an
inert feature. No enforcement code is wired until this test is green.

It proves, with ZERO stubs on the persist/load path:

    real upsert_policy('model_approval')  →  committed rows  →  real RLS load
                                          →  ModelApprovalPolicy(enforcement_mode='default_deny')

Vector 9: real PolicyRepository.upsert_policy(policy_type='model_approval') writes
          both a policies row and a policy_versions row; a real RLS-scoped
          get_active_policies_for_scope(tenant, 'model_approval') loads it back and
          the stored payload parses — through the production construction path
          (ModelApprovalPolicy(**payload), exactly as enforcement.py does) AND
          through parse_variant dispatch — to enforcement_mode='default_deny'.
Also: both CHECK constraints accept 'model_approval' (the upsert proves it) AND
      still reject an unknown policy_type at the DB layer (constraint still live).

DB-GATED: skips gracefully when DATABASE_URL / APP_DATABASE_URL are absent or
Postgres is unreachable. SENTINEL_PROVISION_APP_ROLE=1 required (all real-DB tests).
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
    "skipping real-DB F-019 CRIT-2 persist guard"
)


def _model_approval_payload(*, policy_id, tenant_id, team_id, project_id, agent_id) -> dict:
    """Full model_approval variant record (the stored policy_payload).

    For model policies the stored policy_payload is the FULL variant record:
    enforcement.py builds the typed view via Variant(**json.loads(policy_payload)),
    so the payload must carry the scope IDs + policy_id/version + the variant fields.
    The PRESENCE of this record flips the scope to default-deny; the per-model state
    lives in the inventory, never here (minimal payload by design — ADR-0022 D2).
    """
    return {
        "policy_type": "model_approval",
        "policy_id": policy_id,
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": agent_id,
        "policy_version": 1,
        "enforcement_mode": "default_deny",
    }


@pytest_asyncio.fixture()
async def seeded_tenant():
    """Seed a committed tenant (policies.tenant_id FKs tenants) + cleanup handle."""
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
            {"t": tenant_id, "n": f"f019-{tenant_id[:8]}"},
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


async def test_model_approval_policy_persists_and_loads(seeded_tenant) -> None:
    """Vector 9: real upsert('model_approval') → real RLS load → default-deny view."""
    from persistence.database import get_tenant_session
    from persistence.repositories.policy_repository import PolicyRepository
    from policy.variants import ModelApprovalPolicy, parse_variant
    from policy.variants.model_approval import ModelApprovalPolicy as DirectView

    tenant_id = seeded_tenant["tenant_id"]
    team_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    agent_id = "f019-test"
    policy_id = str(uuid.uuid4())
    payload = _model_approval_payload(
        policy_id=policy_id,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id=agent_id,
    )

    engine = _privileged_engine(seeded_tenant["db_url"])
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    # Persist through the REAL write path (no stubs). A ValueError here would mean
    # 'model_approval' is missing from _VALID_POLICY_TYPES; a CheckViolationError
    # would mean a constraint was not widened — both are the CRIT-2 failure.
    async with factory() as sess:
        async with sess.begin():
            policy, version = await PolicyRepository(sess).upsert_policy(
                policy_id=policy_id,
                policy_type="model_approval",
                policy_version=1,
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=project_id,
                agent_id=agent_id,
                effective_from=datetime.now(timezone.utc),
                signature=_make_jws(),
                policy_payload=payload,
            )
    assert policy.policy_type == "model_approval"
    assert version.policy_type == "model_approval"
    await engine.dispose()

    # Load back through the REAL RLS-scoped session (production load path).
    # DIAGNOSTIC (temporary, CI FD-exhaustion probe): capture the process open-FD
    # count before the connect; on the CI OSError (EAI_AGAIN) print FD count +
    # RLIMIT_NOFILE so we can confirm/deny FD exhaustion. No retry / behavior change.
    # `resource` is imported only in the except (it is unix-only; the local Windows
    # happy path never raises here, so it never imports it).
    try:
        _fd_before = len(os.listdir("/proc/self/fd"))
    except OSError:
        _fd_before = -1
    try:
        async with get_tenant_session(tenant_id) as session:
            rows = await PolicyRepository(session).get_active_policies_for_scope(
                tenant_id, "model_approval"
            )
    except OSError as exc:
        import resource

        try:
            _fd_at = len(os.listdir("/proc/self/fd"))
        except OSError:
            _fd_at = -1
        _soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        raise AssertionError(
            f"DIAG load-back connect failed: open_fds_before={_fd_before} "
            f"open_fds_at_fail={_fd_at} rlimit_nofile soft={_soft} hard={_hard} err={exc!r}"
        ) from exc
    assert len(rows) == 1, "model_approval policy did not load back — feature would be inert"
    loaded = json.loads(rows[0].policy_payload)

    # Production construction path (exactly how enforcement.py builds the view).
    view = DirectView(**loaded)
    assert view.enforcement_mode == "default_deny"
    assert view.tenant_id == tenant_id

    # parse_variant dispatch path (the registry wiring in variants/__init__.py).
    dispatched = parse_variant(loaded)
    assert isinstance(dispatched, ModelApprovalPolicy)
    assert dispatched.enforcement_mode == "default_deny"


async def test_unknown_policy_type_still_rejected_by_db(seeded_tenant) -> None:
    """Widening to model_approval did not loosen the gate — unknown type still rejected.

    Direct privileged INSERT bypasses the app-layer _VALID_POLICY_TYPES check, so
    this exercises the DB CHECK constraint (ck_policies_policy_type) itself.
    """
    import sqlalchemy.exc

    tenant_id = seeded_tenant["tenant_id"]
    engine = _privileged_engine(seeded_tenant["db_url"])
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
