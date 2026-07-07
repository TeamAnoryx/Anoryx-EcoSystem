"""Kill-switch enforcement-state edge detection + RLS (vectors 1,5,6) — DB-backed.

Proves: the conditional transition publishes exactly once under concurrency (vector 5),
versions are monotonic, un-kill flips back, state rows are tenant-isolated (vector 1), and
an unset/empty GUC sees zero rows.
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from delta.kill_switch.state import (
    get_or_create_state,
    try_transition_to_clear,
    try_transition_to_killed,
)
from delta.persistence.database import get_tenant_session

from .conftest import db_required

pytestmark = db_required

_NOW = datetime(2026, 7, 7, 12, 0, 0, tzinfo=timezone.utc)
_TEAM = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_PROJ = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
_AGENT = "rogue-agent"


async def _seed(tenant_session, tenant_id):
    async with tenant_session(tenant_id) as s:
        state = await get_or_create_state(
            s, tenant_id=tenant_id, team_id=_TEAM, project_id=_PROJ, agent_id=_AGENT, now=_NOW
        )
        await s.commit()
    return state


async def test_get_or_create_is_idempotent(tenant_id, tenant_session):
    a = await _seed(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        b = await get_or_create_state(
            s, tenant_id=tenant_id, team_id=_TEAM, project_id=_PROJ, agent_id=_AGENT, now=_NOW
        )
        await s.commit()
    assert a.kill_id == b.kill_id  # same row, not a duplicate
    assert a.policy_id == b.policy_id  # the minted policy_id is stable
    assert b.state == "clear"


async def test_transition_bumps_version_and_is_one_shot(tenant_id, tenant_session):
    state = await _seed(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        v1 = await try_transition_to_killed(
            s, tenant_id=tenant_id, kill_id=state.kill_id, reason="unauthorized_agent", now=_NOW
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        v2 = await try_transition_to_killed(
            s, tenant_id=tenant_id, kill_id=state.kill_id, reason="unauthorized_agent", now=_NOW
        )
        await s.commit()
    assert v1 == 1
    assert v2 is None  # already killed — no second publish


async def test_clear_then_re_kill_monotonic_version(tenant_id, tenant_session):
    state = await _seed(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        assert (
            await try_transition_to_killed(
                s,
                tenant_id=tenant_id,
                kill_id=state.kill_id,
                reason="anomalous_single_tx",
                now=_NOW,
            )
            == 1
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        assert (
            await try_transition_to_clear(s, tenant_id=tenant_id, kill_id=state.kill_id, now=_NOW)
            == 2
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        assert (
            await try_transition_to_killed(
                s,
                tenant_id=tenant_id,
                kill_id=state.kill_id,
                reason="anomalous_single_tx",
                now=_NOW,
            )
            == 3
        )
        await s.commit()


async def test_clear_retains_reason_for_audit(tenant_id, tenant_session):
    state = await _seed(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        await try_transition_to_killed(
            s, tenant_id=tenant_id, kill_id=state.kill_id, reason="unauthorized_agent", now=_NOW
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        await try_transition_to_clear(s, tenant_id=tenant_id, kill_id=state.kill_id, now=_NOW)
        await s.commit()
    async with tenant_session(tenant_id) as s:
        row = await get_or_create_state(
            s, tenant_id=tenant_id, team_id=_TEAM, project_id=_PROJ, agent_id=_AGENT, now=_NOW
        )
        await s.commit()
    assert row.state == "clear"
    assert row.reason == "unauthorized_agent"  # retained, not wiped


async def test_concurrent_offense_exactly_one_winner(tenant_id, tenant_session):
    """vector 5: concurrent offending events for the SAME scope -> exactly one publish."""
    state = await _seed(tenant_session, tenant_id)

    async def _attempt():
        async with get_tenant_session(tenant_id) as s:
            v = await try_transition_to_killed(
                s,
                tenant_id=tenant_id,
                kill_id=state.kill_id,
                reason="anomalous_single_tx",
                now=_NOW,
            )
            await s.commit()
            return v

    results = await asyncio.gather(_attempt(), _attempt(), _attempt())
    winners = [v for v in results if v is not None]
    assert len(winners) == 1, results


async def test_state_rls_isolation(tenant_id, other_tenant_id, tenant_session, read_state):
    await _seed(tenant_session, tenant_id)
    assert len(await read_state(tenant_id)) == 1
    assert await read_state(other_tenant_id) == []


async def test_unset_guc_sees_zero_state_rows(tenant_id, tenant_session):
    """An empty/unset tenant GUC collapses the RLS predicate to zero rows (vector 2)."""
    await _seed(tenant_session, tenant_id)

    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", os.environ["APP_DATABASE_URL"])
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with factory() as s:
            await s.execute(text("SELECT set_config('app.current_tenant_id', '', true)"))
            count = (
                await s.execute(text("SELECT count(*) FROM delta.kill_switch_state"))
            ).scalar_one()
            assert count == 0  # fail-closed: empty GUC -> zero rows, never a widen
    finally:
        await engine.dispose()
