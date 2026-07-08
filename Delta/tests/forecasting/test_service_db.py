"""DB-backed forecast service tests (D-011): real budgets, real ledger rows via the D-004
posting path, real RLS isolation. Every test pins an explicit ``now`` (never the real wall
clock) so period boundaries and elapsed-time math are deterministic.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from delta.budget import BudgetScope
from delta.forecasting.service import forecast_all_budgets, forecast_budget

from .conftest import db_required

pytestmark = db_required

# Mid-July -> period_start=2026-07-01T00:00Z, period_end=2026-08-01T00:00Z (MONTHLY).
_NOW = datetime(2026, 7, 15, 12, 0, 0, tzinfo=timezone.utc)
_PERIOD_START = "2026-07-01T00:00:00Z"


async def test_forecast_returns_none_for_missing_budget(tenant_id, tenant_session):
    async with tenant_session(tenant_id) as s:
        result = await forecast_budget(s, budget_id=str(uuid.uuid4()), now=_NOW)
    assert result is None


async def test_forecast_current_period_spend_and_burn_rate(
    tenant_id, tenant_session, make_budget, seed_usage
):
    budget = await make_budget(tenant_id=tenant_id, cap_cents=10_000_00, scope=BudgetScope.TENANT)
    # $100 spent per day for the first 14 days of the period (14 days elapsed at _NOW).
    for day in range(14):
        await seed_usage(
            tenant_id=tenant_id,
            cost_cents=100_00,
            timestamp=f"2026-07-{day + 1:02d}T06:00:00Z",
        )

    async with tenant_session(tenant_id) as s:
        result = await forecast_budget(s, budget_id=budget.budget_id, now=_NOW)

    assert result is not None
    assert result.insufficient_data is False
    assert result.current_period_spend_cents == 1400_00
    elapsed_hours = (14 * 24) + 12  # 14 full days + 12h into day 15
    expected_rate = 1400_00 / elapsed_hours
    assert result.burn_rate_cents_per_hour == pytest.approx(expected_rate, rel=1e-6)
    assert result.method == "current_rate_projection_v1"


async def test_forecast_cross_tenant_isolation(
    tenant_id, other_tenant_id, tenant_session, make_budget
):
    budget = await make_budget(tenant_id=tenant_id, cap_cents=1000_00)
    async with tenant_session(other_tenant_id) as s:
        result = await forecast_budget(s, budget_id=budget.budget_id, now=_NOW)
    assert result is None  # RLS: another tenant's budget is invisible, not just unlisted


async def test_forecast_already_over_cap(tenant_id, tenant_session, make_budget, seed_usage):
    budget = await make_budget(tenant_id=tenant_id, cap_cents=500_00, scope=BudgetScope.TENANT)
    await seed_usage(tenant_id=tenant_id, cost_cents=900_00, timestamp="2026-07-05T00:00:00Z")

    async with tenant_session(tenant_id) as s:
        result = await forecast_budget(s, budget_id=budget.budget_id, now=_NOW)

    assert result.current_period_spend_cents == 900_00
    codes = [r.code for r in result.recommendations]
    assert "ALREADY_OVER_CAP" in codes
    assert "SOFT_THRESHOLD_CROSSED" not in codes


async def test_forecast_projected_to_exceed(tenant_id, tenant_session, make_budget, seed_usage):
    # A fast, early burn against a cap that will be blown well before period end.
    budget = await make_budget(tenant_id=tenant_id, cap_cents=2000_00, scope=BudgetScope.TENANT)
    for day in range(5):
        await seed_usage(
            tenant_id=tenant_id,
            cost_cents=200_00,
            timestamp=f"2026-07-{day + 1:02d}T06:00:00Z",
        )
    now = datetime(2026, 7, 6, 0, 0, 0, tzinfo=timezone.utc)  # 5 days elapsed

    async with tenant_session(tenant_id) as s:
        result = await forecast_budget(s, budget_id=budget.budget_id, now=now)

    rec = next(r for r in result.recommendations if r.code == "PROJECTED_TO_EXCEED")
    assert rec.severity == "warning"
    assert result.projected_exhaustion_at is not None
    assert result.projected_exhaustion_at < result.period_end


async def test_forecast_no_cost_cap(tenant_id, tenant_session, make_budget, seed_usage):
    budget = await make_budget(tenant_id=tenant_id, cap_cents=None, scope=BudgetScope.TENANT)
    await seed_usage(tenant_id=tenant_id, cost_cents=500_00, timestamp="2026-07-05T00:00:00Z")

    async with tenant_session(tenant_id) as s:
        result = await forecast_budget(s, budget_id=budget.budget_id, now=_NOW)

    assert result.cap_cost_cents is None
    assert [r.code for r in result.recommendations] == ["NO_COST_CAP"]


async def test_forecast_spend_concentration_for_tenant_scoped_budget(
    tenant_id, tenant_session, make_budget, seed_usage
):
    budget = await make_budget(tenant_id=tenant_id, cap_cents=10_000_00, scope=BudgetScope.TENANT)
    big_team = str(uuid.uuid4())
    small_team = str(uuid.uuid4())
    await seed_usage(
        tenant_id=tenant_id, team_id=big_team, cost_cents=700_00, timestamp="2026-07-05T00:00:00Z"
    )
    await seed_usage(
        tenant_id=tenant_id,
        team_id=small_team,
        cost_cents=300_00,
        timestamp="2026-07-05T00:00:00Z",
    )

    async with tenant_session(tenant_id) as s:
        result = await forecast_budget(s, budget_id=budget.budget_id, now=_NOW)

    rec = next(r for r in result.recommendations if r.code == "SPEND_CONCENTRATION")
    assert big_team in rec.message


async def test_forecast_all_budgets_lists_every_tenant_budget(
    tenant_id, tenant_session, make_budget
):
    b1 = await make_budget(tenant_id=tenant_id, cap_cents=1000_00)
    b2 = await make_budget(tenant_id=tenant_id, cap_cents=2000_00, scope=BudgetScope.TEAM)

    async with tenant_session(tenant_id) as s:
        results = await forecast_all_budgets(s, now=_NOW)

    ids = {r.budget_id for r in results}
    assert ids == {b1.budget_id, b2.budget_id}


async def test_forecast_agent_scoped_budget_has_no_concentration_recommendation(
    tenant_id, tenant_session, make_budget, seed_usage
):
    budget = await make_budget(
        tenant_id=tenant_id,
        cap_cents=1000_00,
        scope=BudgetScope.AGENT,
        agent_id="gateway-core",
    )
    await seed_usage(
        tenant_id=tenant_id,
        agent_id="gateway-core",
        cost_cents=100_00,
        timestamp="2026-07-05T00:00:00Z",
    )

    async with tenant_session(tenant_id) as s:
        result = await forecast_budget(s, budget_id=budget.budget_id, now=_NOW)

    # Agent scope is already the finest granularity — no finer breakdown to offer.
    assert "SPEND_CONCENTRATION" not in [r.code for r in result.recommendations]
