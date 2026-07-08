"""D-008 non-stubbed dashboard aggregate suite: real posted usage -> real SQL aggregates.

Every fixture-seeded row goes through the real D-004 posting path (delta.ingest.
posting.post_usage), never a hand-inserted ledger row — proves the aggregates read
the SAME data shape the ingest pipeline actually produces (banked rule #2).
"""

from __future__ import annotations

from datetime import datetime, timezone

from delta.dashboards.store import (
    ScopeFilter,
    spend_for_groups,
    spend_summary,
    spend_time_series,
    top_spenders,
)
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
async def test_time_series_row_count_is_capped(tenant_id, seed_usage, monkeypatch) -> None:
    # Independent security review finding #1: the window-days cap alone still
    # permits thousands of hour-bucket rows. Prove the row-count LIMIT is real
    # without seeding thousands of rows — lower the cap to 2 and seed 3 buckets.
    import delta.dashboards.store as store_module

    monkeypatch.setattr(store_module, "_MAX_TIMESERIES_POINTS", 2)
    await seed_usage(tenant_id=tenant_id, cost_cents=1_000, timestamp="2026-07-01T01:00:00Z")
    await seed_usage(tenant_id=tenant_id, cost_cents=1_000, timestamp="2026-07-01T02:00:00Z")
    await seed_usage(tenant_id=tenant_id, cost_cents=1_000, timestamp="2026-07-01T03:00:00Z")

    async with get_tenant_session(tenant_id) as session:
        points = await spend_time_series(session, start=_START, end=_END, bucket="hour")

    assert len(points) == 2


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
async def test_spend_for_groups_returns_only_requested_keys(tenant_id, seed_usage) -> None:
    agent_a, agent_b, agent_c = "agent-a", "agent-b", "agent-c"
    await seed_usage(tenant_id=tenant_id, agent_id=agent_a, cost_cents=1_000)
    await seed_usage(tenant_id=tenant_id, agent_id=agent_b, cost_cents=2_000)
    await seed_usage(tenant_id=tenant_id, agent_id=agent_c, cost_cents=3_000)

    async with get_tenant_session(tenant_id) as session:
        rows = await spend_for_groups(
            session, start=_START, end=_END, group_by="agent_id", group_keys=[agent_a, agent_c]
        )

    by_key = {r.group_key: r.cost_cents for r in rows}
    assert by_key == {agent_a: 1_000, agent_c: 3_000}  # agent_b never requested, never returned


@db_required
async def test_spend_for_groups_does_not_rank_or_limit(tenant_id, seed_usage) -> None:
    # Unlike top_spenders, every requested group is returned regardless of rank —
    # this is the whole point (D-012 security audit finding #1: a group present in a
    # DIFFERENT window's top-N must not be silently dropped just because it wouldn't
    # independently rank in THIS window's own top-N).
    agent_low, agent_high = "low-spender", "high-spender"
    await seed_usage(tenant_id=tenant_id, agent_id=agent_low, cost_cents=1)
    await seed_usage(tenant_id=tenant_id, agent_id=agent_high, cost_cents=99_999)

    async with get_tenant_session(tenant_id) as session:
        rows = await spend_for_groups(
            session,
            start=_START,
            end=_END,
            group_by="agent_id",
            group_keys=[agent_low, agent_high],
        )

    assert {r.group_key for r in rows} == {agent_low, agent_high}


@db_required
async def test_spend_for_groups_empty_keys_returns_empty_without_querying(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        rows = await spend_for_groups(
            session, start=_START, end=_END, group_by="agent_id", group_keys=[]
        )

    assert rows == []


@db_required
async def test_cross_tenant_spend_is_isolated(tenant_id, other_tenant_id, seed_usage) -> None:
    await seed_usage(tenant_id=tenant_id, cost_cents=5_000)
    await seed_usage(tenant_id=other_tenant_id, cost_cents=7_000)

    async with get_tenant_session(tenant_id) as session:
        row = await spend_summary(session, start=_START, end=_END)

    assert row.total_cost_cents == 5_000  # tenant B's spend never leaks in (RLS)


@db_required
async def test_spend_for_groups_cross_tenant_isolation(
    tenant_id, other_tenant_id, seed_usage
) -> None:
    shared_agent = "shared-agent-id"
    await seed_usage(tenant_id=tenant_id, agent_id=shared_agent, cost_cents=1_000)
    await seed_usage(tenant_id=other_tenant_id, agent_id=shared_agent, cost_cents=9_000)

    async with get_tenant_session(tenant_id) as session:
        rows = await spend_for_groups(
            session, start=_START, end=_END, group_by="agent_id", group_keys=[shared_agent]
        )

    assert len(rows) == 1
    assert rows[0].cost_cents == 1_000  # tenant B's spend on the same group_key never leaks in
