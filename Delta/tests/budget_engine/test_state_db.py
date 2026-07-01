"""Enforcement-state edge detection + RLS (vectors 1,2,5,6) — DB-backed.

Proves: the conditional transition publishes exactly once under concurrency (vector 5),
versions are monotonic, un-enforce flips back (vector 6), state rows are tenant-isolated
(vector 1) and an unset/empty GUC sees zero rows (vector 2).
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope
from delta.budget_engine.definitions import create_budget
from delta.budget_engine.state import (
    get_or_create_state,
    try_bump_warned_pct,
    try_transition_to_enforced,
    try_transition_to_under,
)
from delta.persistence.database import get_tenant_session

from .conftest import db_required

pytestmark = db_required

_NOW = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
_BUCKET = "2026-07-01T00:00:00Z"
_TEAM = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_PROJ = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


async def _make_budget(tenant_session, tenant_id, *, cap=1000):
    concept = BudgetConcept(
        tenant_id=tenant_id,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="gateway-core",
        scope=BudgetScope.TENANT,
        period=BudgetPeriod.DAILY,
        limit_cost_cents=cap,
    )
    async with tenant_session(tenant_id) as s:
        bd = await create_budget(s, concept, now=_NOW)
        await s.commit()
    return bd


async def test_get_or_create_is_idempotent(tenant_id, tenant_session):
    bd = await _make_budget(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        a = await get_or_create_state(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        b = await get_or_create_state(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
        )
        await s.commit()
    assert a.state_id == b.state_id  # same row, not a duplicate
    assert b.state == "under"


async def test_transition_bumps_version_and_is_one_shot(tenant_id, tenant_session):
    bd = await _make_budget(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        await get_or_create_state(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        v1 = await try_transition_to_enforced(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        v2 = await try_transition_to_enforced(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
        )
        await s.commit()
    assert v1 == 1  # first publish, version 1
    assert v2 is None  # already enforced — no second publish


async def test_un_enforce_then_re_enforce_monotonic_version(tenant_id, tenant_session):
    bd = await _make_budget(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        await get_or_create_state(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        assert (
            await try_transition_to_enforced(
                s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
            )
            == 1
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        assert (
            await try_transition_to_under(
                s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
            )
            == 2
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        assert (
            await try_transition_to_enforced(
                s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
            )
            == 3
        )
        await s.commit()


async def test_concurrent_transition_exactly_one_winner(tenant_id, tenant_session):
    """Two concurrent appends both cross the cap -> exactly ONE flips/publishes (vector 5)."""
    bd = await _make_budget(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        await get_or_create_state(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
        )
        await s.commit()

    async def _attempt():
        async with get_tenant_session(tenant_id) as s:
            v = await try_transition_to_enforced(
                s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
            )
            await s.commit()
            return v

    results = await asyncio.gather(_attempt(), _attempt(), _attempt())
    winners = [v for v in results if v is not None]
    assert len(winners) == 1, results  # exactly one publish across concurrent attempts


async def test_version_monotonic_across_periods(tenant_id, tenant_session):
    """H-1: a new period must NOT reset policy_version (else the outbox INSERT silently no-ops).

    policy_version is monotonic per policy_id GLOBALLY (the outbox UNIQUE + Sentinel replay are
    per-policy_id, not per-period). A new period's state row seeds last_published_version from
    the global max for this (tenant, budget), so the next crossing yields a fresh, higher
    version — never a re-used one whose outbox INSERT would no-op (a missed enforcement).
    """
    bd = await _make_budget(tenant_session, tenant_id)
    bucket1 = "2026-07-01T00:00:00Z"
    bucket2 = "2026-08-01T00:00:00Z"  # the next monthly period

    async with tenant_session(tenant_id) as s:
        await get_or_create_state(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=bucket1, now=_NOW
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        v1 = await try_transition_to_enforced(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=bucket1, now=_NOW
        )
        await s.commit()

    # New period: get_or_create_state must seed from the prior global max (1), not 0.
    async with tenant_session(tenant_id) as s:
        seeded = await get_or_create_state(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=bucket2, now=_NOW
        )
        await s.commit()
    assert seeded.last_published_version == 1  # seeded from period-1's high-water mark

    async with tenant_session(tenant_id) as s:
        v2 = await try_transition_to_enforced(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=bucket2, now=_NOW
        )
        await s.commit()
    assert v1 == 1 and v2 == 2  # globally monotonic across periods — NOT a re-used version 1


async def test_state_rls_isolation(tenant_id, other_tenant_id, tenant_session, read_state):
    bd = await _make_budget(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        await get_or_create_state(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
        )
        await s.commit()
    # tenant A sees its row; tenant B sees nothing (RLS).
    assert len(await read_state(tenant_id)) == 1
    assert await read_state(other_tenant_id) == []


async def test_unset_guc_sees_zero_state_rows(tenant_id, tenant_session):
    """An empty/unset tenant GUC collapses the RLS predicate to zero rows (vector 2)."""
    import os

    bd = await _make_budget(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        await get_or_create_state(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
        )
        await s.commit()

    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", os.environ["APP_DATABASE_URL"])
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        async with factory() as s:
            await s.execute(text("SELECT set_config('app.current_tenant_id', '', true)"))
            count = (
                await s.execute(text("SELECT count(*) FROM delta.budget_enforcement_state"))
            ).scalar_one()
            assert count == 0  # fail-closed: empty GUC -> zero rows, never a widen
    finally:
        await engine.dispose()


async def test_warned_pct_edge_dedup(tenant_id, tenant_session):
    bd = await _make_budget(tenant_session, tenant_id)
    async with tenant_session(tenant_id) as s:
        await get_or_create_state(
            s, tenant_id=tenant_id, budget_id=bd.budget_id, period_bucket=_BUCKET, now=_NOW
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        assert (
            await try_bump_warned_pct(
                s,
                tenant_id=tenant_id,
                budget_id=bd.budget_id,
                period_bucket=_BUCKET,
                pct=80,
                now=_NOW,
            )
            is True
        )
        await s.commit()
    async with tenant_session(tenant_id) as s:
        # 80 already warned -> no re-warn; a higher band 95 does warn.
        assert (
            await try_bump_warned_pct(
                s,
                tenant_id=tenant_id,
                budget_id=bd.budget_id,
                period_bucket=_BUCKET,
                pct=80,
                now=_NOW,
            )
            is False
        )
        assert (
            await try_bump_warned_pct(
                s,
                tenant_id=tenant_id,
                budget_id=bd.budget_id,
                period_bucket=_BUCKET,
                pct=95,
                now=_NOW,
            )
            is True
        )
        await s.commit()
