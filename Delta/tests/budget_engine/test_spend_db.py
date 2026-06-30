"""Spend derivation over the real ledger (vectors 3+4) — DB-backed.

Proves cumulative spend is summed from committed debits, integer cents, scope/period
filtered, and tenant-isolated by RLS.
"""

from __future__ import annotations

from datetime import datetime, timezone

from delta.budget import BudgetScope
from delta.budget_engine.spend import scope_spend_cents

from .conftest import db_required

pytestmark = db_required

_PSTART = datetime(2026, 7, 1, 0, 0, 0, tzinfo=timezone.utc)
_NOW = datetime(2026, 7, 1, 23, 0, 0, tzinfo=timezone.utc)


async def _spend(tenant_session, tenant_id, scope, **ids) -> int:
    async with tenant_session(tenant_id) as s:
        return await scope_spend_cents(
            s,
            scope=scope,
            tenant_id=tenant_id,
            team_id=ids.get("team_id", "t"),
            project_id=ids.get("project_id", "p"),
            agent_id=ids.get("agent_id", "a"),
            currency=ids.get("currency", "USD"),
            period_start=_PSTART,
            period_end=_NOW,
        )


async def test_tenant_scope_sums_all_debits(
    tenant_id, make_usage_payload, post_debit, tenant_session
):
    await post_debit(make_usage_payload(tenant_id, cost=1000))
    await post_debit(make_usage_payload(tenant_id, cost=2500))
    spend = await _spend(tenant_session, tenant_id, BudgetScope.TENANT)
    assert spend == 3500
    assert isinstance(spend, int)


async def test_team_scope_filters_by_team(
    tenant_id, make_usage_payload, post_debit, tenant_session
):
    team = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    other_team = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    await post_debit(make_usage_payload(tenant_id, team_id=team, cost=1000))
    await post_debit(make_usage_payload(tenant_id, team_id=other_team, cost=9999))
    spend = await _spend(tenant_session, tenant_id, BudgetScope.TEAM, team_id=team)
    assert spend == 1000  # only the matching team's debit


async def test_project_and_agent_scope_filter(
    tenant_id, make_usage_payload, post_debit, tenant_session
):
    proj = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    await post_debit(make_usage_payload(tenant_id, project_id=proj, agent_id="agent-x", cost=700))
    await post_debit(make_usage_payload(tenant_id, agent_id="agent-y", cost=300))
    assert await _spend(tenant_session, tenant_id, BudgetScope.PROJECT, project_id=proj) == 700
    assert await _spend(tenant_session, tenant_id, BudgetScope.AGENT, agent_id="agent-x") == 700
    assert await _spend(tenant_session, tenant_id, BudgetScope.AGENT, agent_id="agent-y") == 300


async def test_window_excludes_out_of_period(
    tenant_id, make_usage_payload, post_debit, tenant_session
):
    # An event before the window start is not counted (half-open [start, now)).
    await post_debit(
        make_usage_payload(tenant_id, cost=500) | {"event_timestamp": "2026-06-30T23:59:59Z"}
    )
    await post_debit(make_usage_payload(tenant_id, cost=800))  # in-window (12:00)
    assert await _spend(tenant_session, tenant_id, BudgetScope.TENANT) == 800


async def test_spend_is_tenant_isolated(
    tenant_id, other_tenant_id, make_usage_payload, post_debit, tenant_session
):
    await post_debit(make_usage_payload(tenant_id, cost=4242))
    await post_debit(make_usage_payload(other_tenant_id, cost=9999))
    # RLS: each tenant's session sees only its own debits.
    assert await _spend(tenant_session, tenant_id, BudgetScope.TENANT) == 4242
    assert await _spend(tenant_session, other_tenant_id, BudgetScope.TENANT) == 9999


async def test_no_debits_is_zero(tenant_id, tenant_session):
    assert await _spend(tenant_session, tenant_id, BudgetScope.TENANT) == 0


async def test_spend_nets_to_zero_after_reversal(tenant_id, make_usage_payload, tenant_session):
    """A reversed usage nets to 0, not 2x cost (the FALSE-ENFORCEMENT fix; review HIGH).

    Spend is the NET expense balance; a raw debit-sum across all accounts would count the
    reversal's contra-account debit and report 2x cost -> wrongly enforce.
    """
    import uuid

    from delta.ingest.posting import build_usage_record, post_usage
    from delta.persistence.ledger_store import reverse_transaction

    rec = build_usage_record(make_usage_payload(tenant_id, cost=3000))
    result = await post_usage(rec)
    assert await _spend(tenant_session, tenant_id, BudgetScope.TENANT) == 3000

    async with tenant_session(tenant_id) as s:
        await reverse_transaction(
            s,
            result.txn_id,
            new_txn_id=str(uuid.uuid4()),
            timestamp=datetime(2026, 7, 1, 13, 0, 0, tzinfo=timezone.utc),
        )
        await s.commit()

    assert await _spend(tenant_session, tenant_id, BudgetScope.TENANT) == 0
