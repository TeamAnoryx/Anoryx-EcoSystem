"""D-020 service-layer DB tests: the composed rollup across D-008 spend, D-011
forecasts, and D-013 pipeline."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from delta.executive.schemas import ExecutiveSummaryQuery
from delta.executive.service import get_executive_summary

from .conftest import db_required, open_tenant_session, seed_client_and_deal

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)


@db_required
async def test_executive_summary_composes_spend_forecast_and_pipeline(
    tenant_id, make_budget, seed_usage
) -> None:
    team_id = "11111111-1111-4111-8111-111111111111"
    project_id = "22222222-2222-4222-8222-222222222222"

    await make_budget(
        tenant_id=tenant_id,
        cap_cents=100_000,
        team_id=team_id,
        project_id=project_id,
    )
    await seed_usage(
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        cost_cents=5_000,
        timestamp=(_NOW - timedelta(hours=2)).isoformat(),
    )
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=75_000, stage="qualified")
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=25_000, stage="won")

    async with open_tenant_session(tenant_id) as session:
        summary = await get_executive_summary(
            session,
            ExecutiveSummaryQuery(tenant_id=tenant_id, start=_NOW - timedelta(days=1), end=_NOW),
            now=_NOW,
        )

    assert summary.total_cost_cents == 5_000
    assert summary.request_count == 1
    assert summary.budget_count == 1
    assert summary.budgets_truncated is False
    assert summary.total_current_period_spend_cents == 5_000
    assert summary.client_count == 2
    assert summary.open_deal_count == 1  # the 'won' deal is excluded
    assert summary.open_pipeline_value_minor_units == 75_000
    assert summary.pipeline_currency == "USD"


@db_required
async def test_executive_summary_zero_state_for_empty_tenant(tenant_id) -> None:
    async with open_tenant_session(tenant_id) as session:
        summary = await get_executive_summary(
            session,
            ExecutiveSummaryQuery(tenant_id=tenant_id, start=_NOW - timedelta(days=1), end=_NOW),
            now=_NOW,
        )

    assert summary.total_cost_cents == 0
    assert summary.budget_count == 0
    assert summary.budgets_truncated is False
    assert summary.total_projected_period_end_spend_cents is None
    assert summary.client_count == 0
    assert summary.open_deal_count == 0
    assert summary.open_pipeline_value_minor_units == 0


@db_required
async def test_executive_summary_counts_critical_budget(tenant_id, make_budget, seed_usage) -> None:
    team_id = "33333333-3333-4333-8333-333333333333"
    project_id = "44444444-4444-4444-8444-444444444444"

    # A tiny cap blown through immediately should trigger a 'critical' recommendation
    # (mirrors D-011's own recommendation thresholds, exercised end-to-end here rather
    # than re-asserted — that logic is D-011's, not D-020's, to test).
    await make_budget(tenant_id=tenant_id, cap_cents=100, team_id=team_id, project_id=project_id)
    await seed_usage(
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        cost_cents=10_000,
        timestamp=(_NOW - timedelta(hours=1)).isoformat(),
    )

    async with open_tenant_session(tenant_id) as session:
        summary = await get_executive_summary(
            session,
            ExecutiveSummaryQuery(tenant_id=tenant_id, start=_NOW - timedelta(days=1), end=_NOW),
            now=_NOW,
        )

    assert summary.budget_count == 1
    assert summary.budgets_at_critical == 1
    assert summary.budgets_at_warning == 0


@db_required
async def test_executive_summary_cross_tenant_isolated(
    tenant_id, other_tenant_id, make_budget, seed_usage
) -> None:
    await seed_client_and_deal(tenant_id=tenant_id, value_minor_units=50_000, stage="qualified")
    await make_budget(tenant_id=tenant_id, cap_cents=100_000)
    await seed_usage(
        tenant_id=tenant_id, cost_cents=1_000, timestamp=(_NOW - timedelta(hours=1)).isoformat()
    )

    async with open_tenant_session(other_tenant_id) as session:
        summary = await get_executive_summary(
            session,
            ExecutiveSummaryQuery(
                tenant_id=other_tenant_id, start=_NOW - timedelta(days=1), end=_NOW
            ),
            now=_NOW,
        )

    assert summary.total_cost_cents == 0
    assert summary.budget_count == 0
    assert summary.client_count == 0


@db_required
async def test_executive_summary_signals_budgets_truncated_at_the_forecast_cap(
    tenant_id, make_budget
) -> None:
    # _MAX_FORECAST_BUDGETS (service.py) is 25 — mirrors forecasting.router's own
    # cost-conscious list cap. A tenant with at least that many budgets must see an
    # honest truncation signal rather than a total that silently under-counts
    # (security audit finding, ADR-0020 §2 Fork 8).
    for _ in range(25):
        await make_budget(tenant_id=tenant_id, cap_cents=100_000)

    async with open_tenant_session(tenant_id) as session:
        summary = await get_executive_summary(
            session,
            ExecutiveSummaryQuery(tenant_id=tenant_id, start=_NOW - timedelta(days=1), end=_NOW),
            now=_NOW,
        )

    assert summary.budget_count == 25
    assert summary.budgets_truncated is True
