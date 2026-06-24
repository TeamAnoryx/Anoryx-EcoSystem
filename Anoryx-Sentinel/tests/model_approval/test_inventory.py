"""F-019 model inventory: tenant isolation (vector 10) + state machine (ADR-0022 §5.2).

Vector 10: one tenant's inventory + approvals are RLS-scoped — invisible AND unusable
to another tenant. Proven on the REAL RLS path (get_tenant_session sets the
app.current_tenant_id GUC; the model_inventory tenant_isolation policy filters rows),
not just the explicit predicate: a tenant-B session querying with tenant-A's id still
sees nothing.

State machine: adopt creates pending; valid edges pending→approved, pending→denied,
approved→denied, denied→approved; illegal edges + transitions on absent models raise.

DB-GATED via the package conftest. SENTINEL_PROVISION_APP_ROLE=1 required.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone

import asyncpg
import pytest
import pytest_asyncio
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)

pytestmark = pytest.mark.asyncio

_SKIP_REASON = (
    "DATABASE_URL / APP_DATABASE_URL not set or Postgres unreachable — "
    "skipping real-DB F-019 inventory tests"
)


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _privileged_engine(db_url: str):
    return create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


@pytest_asyncio.fixture()
async def two_tenants():
    """Seed two committed tenants (A, B) + cleanup of their inventory/tenant rows."""
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
    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    engine = _privileged_engine(db_url)
    async with engine.begin() as conn:
        for tid in (a, b):
            await conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                    "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
                ),
                {"t": tid, "n": f"f019-{tid[:8]}"},
            )
    await engine.dispose()

    async def _cleanup() -> None:
        ce = _privileged_engine(db_url)
        try:
            async with ce.begin() as conn:
                for tid in (a, b):
                    await conn.execute(
                        text("DELETE FROM model_inventory WHERE tenant_id = :t"), {"t": tid}
                    )
                    await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tid})
        finally:
            await ce.dispose()

    yield {"a": a, "b": b}
    await _cleanup()


async def test_inventory_tenant_scoped(two_tenants) -> None:
    """Vector 10: tenant A's approved model is invisible + unusable to tenant B."""
    from persistence.database import get_tenant_session
    from persistence.repositories.model_inventory_repository import (
        UNKNOWN_STATE,
        ModelInventoryRepository,
    )

    a, b = two_tenants["a"], two_tenants["b"]
    model = "gpt-4o-tenantA"
    now = datetime.now(timezone.utc)

    # Tenant A adopts + approves the model (real RLS write path).
    async with get_tenant_session(a) as sess:
        repo = ModelInventoryRepository(sess)
        await repo.adopt(a, model, "base")
        await repo.transition(a, model, "approved", operator_id="op-A", now=now)
        await sess.commit()

    # Tenant B cannot see it — neither via its own id nor by passing A's id.
    async with get_tenant_session(b) as sess:
        repo = ModelInventoryRepository(sess)
        assert await repo.list_for_tenant(b) == []
        assert await repo.get_state(b, model) == UNKNOWN_STATE
        # RLS (GUC=B), not just the predicate: querying with A's id still sees nothing.
        assert await repo.get_state(a, model) == UNKNOWN_STATE
        assert await repo.get_row(a, model) is None

    # Tenant A still sees its own approved row.
    async with get_tenant_session(a) as sess:
        repo = ModelInventoryRepository(sess)
        assert await repo.get_state(a, model) == "approved"
        rows = await repo.list_for_tenant(a)
        assert len(rows) == 1 and rows[0].model_id == model


async def test_state_machine_valid_and_invalid_edges(two_tenants) -> None:
    """adopt→pending; valid edges walk; illegal edges + absent model raise."""
    from persistence.database import get_tenant_session
    from persistence.repositories.model_inventory_repository import (
        InvalidModelTransitionError,
        ModelInventoryNotFoundError,
        ModelInventoryRepository,
    )

    a = two_tenants["a"]
    model = "fine-tune-X"
    now = datetime.now(timezone.utc)

    async with get_tenant_session(a) as sess:
        repo = ModelInventoryRepository(sess)

        row, created = await repo.adopt(a, model, "fine_tune")
        assert row.state == "pending"
        assert row.model_type == "fine_tune"
        assert created is True  # newly inserted

        # adopt is idempotent — does not reset an existing row, reports created=False.
        again, created_again = await repo.adopt(a, model, "fine_tune")
        assert again.state == "pending"
        assert created_again is False

        # Valid walk: pending → approved → denied → approved.
        await repo.transition(a, model, "approved", operator_id="op", now=now)
        assert (await repo.get_state(a, model)) == "approved"
        await repo.transition(a, model, "denied", operator_id="op", now=now)
        assert (await repo.get_state(a, model)) == "denied"
        await repo.transition(a, model, "approved", operator_id="op", now=now)
        assert (await repo.get_state(a, model)) == "approved"

        # Illegal: approved → pending is not a permitted edge.
        with pytest.raises(InvalidModelTransitionError):
            await repo.transition(a, model, "pending", operator_id="op", now=now)

        # Illegal: same-state request.
        with pytest.raises(InvalidModelTransitionError):
            await repo.transition(a, model, "approved", operator_id="op", now=now)

        # Absent model → not found.
        with pytest.raises(ModelInventoryNotFoundError):
            await repo.transition(a, "no-such-model", "approved", operator_id="op", now=now)

        await sess.commit()
