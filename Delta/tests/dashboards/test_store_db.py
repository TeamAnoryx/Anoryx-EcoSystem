"""D-008 non-stubbed dashboard aggregate suite: real posted usage -> real SQL aggregates.

Every fixture-seeded row goes through the real D-004 posting path (delta.ingest.
posting.post_usage), never a hand-inserted ledger row — proves the aggregates read
the SAME data shape the ingest pipeline actually produces (banked rule #2).
"""

from __future__ import annotations

from datetime import datetime, timezone

from delta.dashboards.store import ScopeFilter, spend_summary, spend_time_series, top_spenders
from delta.persistence.database import get_tenant_session

from .conftest import db_required

_START = datetime(2026, 7, 1, tzinfo=timezone.utc)
_END = datetime(2026, 7, 3, tzinfo=timezone.utc)


@db_required
async def test_spend_summary_counts_debit_leg_once(tenant_id, seed_usage) -> None:
    await seed_usage(tenant_id=tenant_id, cost_cents=1_000, timestamp="2026-07-01T12:00:00Z")
    await seed_usage(tenant_id=tenant_id, cost_cents=2_500, timestamp="2026-07-02T08:00:00Z")

    async with get_tenant_session(tenant_id) as session:
        row = await spend_summary(session, start=_START, end=_END)

    # Not double-counted (both ledger legs of each txn would sum to zero if we
    # summed all directions, or double-count if we ignored direction entirely).
    assert row.total_cost_cents == 3_500
    assert row.request_count == 2
    assert row.cost_per_request_cents == 1_750.0


@db_required
async def test_spend_summary_out_of_window_excluded(tenant_id, seed_usage) -> None:
    await seed_usage(tenant_id=tenant_id, cost_cents=1_000, timestamp="2026-06-15T12:00:00Z")

    async with get_tenant_session(tenant_id) as session:
        row = await spend_summary(session, start=_START, end=_END)

    assert row.total_cost_cents == 0
    assert row.request_count == 0
    assert row.cost_per_request_cents is None


@db_required
async def test_spend_summary_scoped_to_team(tenant_id, seed_usage) -> None:
    team_a, team_b = "team-a-scope-test", "team-b-scope-test"
    import uuid

    team_a_id, team_b_id = str(uuid.uuid4()), str(uuid.uuid4())
    await seed_usage(tenant_id=tenant_id, team_id=team_a_id, cost_cents=1_000)
    await seed_usage(tenant_id=tenant_id, team_id=team_b_id, cost_cents=9_000)

    async with get_tenant_session(tenant_id) as session:
        row = await spend_summary(
            session, start=_START, end=_END, scope=ScopeFilter(team_id=team_a_id)
        )

    assert row.total_cost_cents == 1_000
    assert row.request_count == 1
    del team_a, team_b  # unused labels, kept for readability of intent above


@db_required
async def test_time_series_buckets_by_day(tenant_id, seed_usage) -> None:
    await seed_usage(tenant_id=tenant_id, cost_cents=1_000, timestamp="2026-07-01T01:00:00Z")
    await seed_usage(tenant_id=tenant_id, cost_cents=500, timestamp="2026-07-01T23:00:00Z")
    await seed_usage(tenant_id=tenant_id, cost_cents=2_000, timestamp="2026-07-02T05:00:00Z")

    async with get_tenant_session(tenant_id) as session:
        points = await spend_time_series(session, start=_START, end=_END, bucket="day")

    assert len(points) == 2
    assert points[0].bucket_start == datetime(2026, 7, 1, tzinfo=timezone.utc)
    assert points[0].cost_cents == 1_500
    assert points[0].request_count == 2
    assert points[1].bucket_start == datetime(2026, 7, 2, tzinfo=timezone.utc)
    assert points[1].cost_cents == 2_000
    assert points[1].request_count == 1


@db_required
async def test_top_spenders_ranks_by_cost_desc(tenant_id, seed_usage) -> None:
    import uuid

    agent_low, agent_high = "low-spender", "high-spender"
    await seed_usage(tenant_id=tenant_id, agent_id=agent_low, cost_cents=100)
    await seed_usage(tenant_id=tenant_id, agent_id=agent_high, cost_cents=9_999)
    await seed_usage(
        tenant_id=tenant_id, agent_id=agent_high, cost_cents=1, team_id=str(uuid.uuid4())
    )

    async with get_tenant_session(tenant_id) as session:
        rows = await top_spenders(session, start=_START, end=_END, group_by="agent_id", limit=1)

    assert len(rows) == 1
    assert rows[0].group_key == agent_high
    assert rows[0].cost_cents == 10_000
    assert rows[0].request_count == 2


@db_required
async def test_cross_tenant_spend_is_isolated(tenant_id, other_tenant_id, seed_usage) -> None:
    await seed_usage(tenant_id=tenant_id, cost_cents=5_000)
    await seed_usage(tenant_id=other_tenant_id, cost_cents=7_000)

    async with get_tenant_session(tenant_id) as session:
        row = await spend_summary(session, start=_START, end=_END)

    assert row.total_cost_cents == 5_000  # tenant B's spend never leaks in (RLS)
