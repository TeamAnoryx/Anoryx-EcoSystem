"""F-019 default-deny enforcement — vectors 5,6,7,8 (ADR-0022 §5.3).

Exercises the REAL evaluate_model_policies seam (the F-006 router call site) on a
tenant RLS session, with a committed model_approval policy + real inventory rows —
no stubs on the approval/inventory/decision path:

  6  test_approved_model_allowed          — approval active + state approved -> ModelAllow
  5  test_unapproved_model_denied          — approval active + pending/unknown -> ModelDeny
  8  test_denied_model_blocked             — approval active + state denied -> ModelDeny
  7  test_enforcement_fails_closed         — inventory-load error -> ModelDeny (fail-closed)
  +  test_no_approval_policy_preserves_f008 — NO approval policy -> unknown model ALLOWED
                                              (F-008 opt-in semantics untouched; the
                                              tenants who don't use F-019 are unaffected)

DB-GATED via the package conftest. SENTINEL_PROVISION_APP_ROLE=1 required.
"""

from __future__ import annotations

import base64
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

_SKIP_REASON = (
    "DATABASE_URL / APP_DATABASE_URL not set or Postgres unreachable — "
    "skipping real-DB F-019 enforcement tests"
)


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _make_jws() -> str:
    seg = base64.urlsafe_b64encode(b"x" * 20).decode().rstrip("=")
    return f"{seg}.{seg}.{seg}"


def _privileged_engine(db_url: str):
    return create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


@pytest_asyncio.fixture()
async def seeded_tenant():
    """Commit a tenant + cleanup of its policies / inventory / tenant rows."""
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
                    text("DELETE FROM model_inventory WHERE tenant_id = :t"), {"t": tenant_id}
                )
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


async def _write_approval_policy(db_url: str, tenant_id: str) -> None:
    """Commit a tenant-wide (wildcard) model_approval policy via the REAL repo path."""
    from persistence.repositories.policy_repository import PolicyRepository
    from policy.constants import WILDCARD_AGENT, WILDCARD_UUID

    policy_id = str(uuid.uuid4())
    payload = {
        "policy_type": "model_approval",
        "policy_id": policy_id,
        "tenant_id": tenant_id,
        "team_id": WILDCARD_UUID,
        "project_id": WILDCARD_UUID,
        "agent_id": WILDCARD_AGENT,
        "policy_version": 1,
        "enforcement_mode": "default_deny",
    }
    engine = _privileged_engine(db_url)
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )
    async with factory() as sess:
        async with sess.begin():
            await PolicyRepository(sess).upsert_policy(
                policy_id=policy_id,
                policy_type="model_approval",
                policy_version=1,
                tenant_id=tenant_id,
                team_id=WILDCARD_UUID,
                project_id=WILDCARD_UUID,
                agent_id=WILDCARD_AGENT,
                effective_from=datetime.now(timezone.utc),
                signature=_make_jws(),
                policy_payload=payload,
            )
    await engine.dispose()


async def _set_inventory(tenant_id: str, model: str, state: str) -> None:
    """Adopt a model and (if needed) transition it to the target state — RLS write."""
    from persistence.database import get_tenant_session
    from persistence.repositories.model_inventory_repository import ModelInventoryRepository

    now = datetime.now(timezone.utc)
    async with get_tenant_session(tenant_id) as sess:
        repo = ModelInventoryRepository(sess)
        await repo.adopt(tenant_id, model, "base")
        if state != "pending":
            await repo.transition(tenant_id, model, state, operator_id="op", now=now)
        await sess.commit()


def _scope(tenant_id: str):
    from policy.enforcement import RequestScope

    return RequestScope(
        tenant_id=tenant_id,
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="enforce-test",
    )


async def _evaluate(tenant_id: str, model: str):
    from persistence.database import get_tenant_session
    from policy.enforcement import evaluate_model_policies

    # get_tenant_session autobegins (set_config opens the tx); evaluate_model_policies
    # only reads, so no nested begin()/commit() — matches the read pattern in
    # admin/control.py. The production live-path wrapping (selection.py) is covered by
    # the vector-12 non-stubbed e2e.
    async with get_tenant_session(tenant_id) as sess:
        return await evaluate_model_policies(sess, _scope(tenant_id), model)


async def test_approved_model_allowed(seeded_tenant) -> None:
    """Vector 6: approval mode active + model approved -> ModelAllow."""
    from policy.enforcement import ModelAllow

    t = seeded_tenant["tenant_id"]
    await _write_approval_policy(seeded_tenant["db_url"], t)
    await _set_inventory(t, "gpt-4o", "approved")
    assert isinstance(await _evaluate(t, "gpt-4o"), ModelAllow)


async def test_unapproved_model_denied(seeded_tenant) -> None:
    """Vector 5: approval mode active + pending/unknown model -> ModelDeny."""
    from policy.enforcement import ModelDeny

    t = seeded_tenant["tenant_id"]
    await _write_approval_policy(seeded_tenant["db_url"], t)
    await _set_inventory(t, "gpt-4o", "pending")

    pending_dec = await _evaluate(t, "gpt-4o")
    assert isinstance(pending_dec, ModelDeny)
    assert pending_dec.reason == "model_not_approved"

    # An UNKNOWN model (never adopted) is also default-denied.
    unknown_dec = await _evaluate(t, "never-seen-model")
    assert isinstance(unknown_dec, ModelDeny)
    assert unknown_dec.reason == "model_not_approved"


async def test_denied_model_blocked(seeded_tenant) -> None:
    """Vector 8: a model moved to 'denied' is blocked on the next request."""
    from policy.enforcement import ModelDeny

    t = seeded_tenant["tenant_id"]
    await _write_approval_policy(seeded_tenant["db_url"], t)
    await _set_inventory(t, "gpt-4o", "approved")
    # Operator denies it; the next evaluation must block.
    await _set_inventory(t, "gpt-4o", "denied")
    dec = await _evaluate(t, "gpt-4o")
    assert isinstance(dec, ModelDeny)
    assert dec.reason == "model_not_approved"


async def test_enforcement_fails_closed(seeded_tenant, monkeypatch) -> None:
    """Vector 7: an inventory-load error DENIES (fail-closed), never allows."""
    from persistence.repositories import model_inventory_repository as mod
    from policy.enforcement import ModelDeny

    t = seeded_tenant["tenant_id"]
    await _write_approval_policy(seeded_tenant["db_url"], t)
    await _set_inventory(t, "gpt-4o", "approved")  # would be ALLOW absent the fault

    async def _boom(self, tenant_id, model_id):  # noqa: ANN001
        raise RuntimeError("inventory backend unavailable")

    # F-021: enforcement reads get_row (the retire_at deadline needs the full row);
    # the fail-closed try/except wraps that call. Patch get_row, not get_state.
    monkeypatch.setattr(mod.ModelInventoryRepository, "get_row", _boom)
    dec = await _evaluate(t, "gpt-4o")
    assert isinstance(dec, ModelDeny)
    assert dec.reason == "model_not_approved"


async def _set_retirement(tenant_id: str, model: str, retire_at: datetime) -> None:
    """Set retire_at on an APPROVED model via the REAL repo path (RLS write)."""
    from persistence.database import get_tenant_session
    from persistence.repositories.model_inventory_repository import ModelInventoryRepository

    now = datetime.now(timezone.utc)
    async with get_tenant_session(tenant_id) as sess:
        await ModelInventoryRepository(sess).set_retirement(tenant_id, model, retire_at, now=now)
        await sess.commit()


async def test_in_grace_model_still_allowed(seeded_tenant) -> None:
    """F-021 vector 6: an approved model with a FUTURE retire_at is still ALLOWED.

    Real path: approval active + state approved + retire_at far in the future
    (within grace) -> ModelAllow. The deadline does not bite until it passes.
    """
    from datetime import timedelta

    from policy.enforcement import ModelAllow

    t = seeded_tenant["tenant_id"]
    await _write_approval_policy(seeded_tenant["db_url"], t)
    await _set_inventory(t, "gpt-4o", "approved")
    await _set_retirement(t, "gpt-4o", datetime.now(timezone.utc) + timedelta(days=30))
    assert isinstance(await _evaluate(t, "gpt-4o"), ModelAllow)


async def test_past_grace_model_denied(seeded_tenant) -> None:
    """F-021 vector 5: an approved model PAST its retire_at is DENIED (fail-closed).

    Real path (no stub on the inventory/decision chain): approval active + state
    approved + retire_at in the PAST -> ModelDeny(reason='model_retired'). Proves the
    retirement enforcement is NOT inert — a retired model is actually blocked.
    """
    from datetime import timedelta

    from policy.enforcement import ModelDeny

    t = seeded_tenant["tenant_id"]
    await _write_approval_policy(seeded_tenant["db_url"], t)
    await _set_inventory(t, "gpt-4o", "approved")
    # retire_at one hour in the PAST (the repo allows a past deadline; the API guards
    # against it — this exercises the enforcement seam directly).
    await _set_retirement(t, "gpt-4o", datetime.now(timezone.utc) - timedelta(hours=1))

    dec = await _evaluate(t, "gpt-4o")
    assert isinstance(dec, ModelDeny)
    assert dec.reason == "model_retired"


async def test_no_approval_policy_preserves_f008(seeded_tenant) -> None:
    """No model_approval policy -> F-008 opt-in stands: an unknown model is ALLOWED.

    Guards the core promise that F-019 does NOT change behavior for tenants who do
    not opt in: with no model_approval policy, evaluate_model_policies returns
    ModelAllow for a model that has no inventory row (exactly pre-F-019 behavior).
    """
    from policy.enforcement import ModelAllow

    t = seeded_tenant["tenant_id"]
    # No approval policy written, no inventory. An arbitrary model is not constrained.
    assert isinstance(await _evaluate(t, "anything-goes"), ModelAllow)
