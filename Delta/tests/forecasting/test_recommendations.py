"""Pure recommendation-building logic: no I/O, no DB (D-011, ADR-0011 §2 fork 2)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from delta.budget import BudgetPeriod, BudgetScope
from delta.budget_engine.definitions import BudgetDefinition
from delta.dashboards.store import GroupSpendRow
from delta.forecasting.projection import Projection
from delta.forecasting.recommendations import build_recommendations

_START = datetime(2026, 7, 1, tzinfo=timezone.utc)
_END = datetime(2026, 8, 1, tzinfo=timezone.utc)


def _budget(limit_cost_cents: int | None) -> BudgetDefinition:
    return BudgetDefinition(
        budget_id="b",
        tenant_id="11111111-1111-4111-8111-111111111111",
        scope=BudgetScope.TENANT,
        team_id="22222222-2222-4222-8222-222222222222",
        project_id="33333333-3333-4333-8333-333333333333",
        agent_id="gateway-core",
        period=BudgetPeriod.MONTHLY,
        limit_tokens=None,
        limit_cost_cents=limit_cost_cents,
        currency="USD",
        policy_id="44444444-4444-4444-8444-444444444444",
    )


def _projection(
    *,
    current_period_spend_cents: int,
    burn_rate_cents_per_hour: float = 0.0,
    projected_period_end_spend_cents: float | None = None,
    trend_direction: str | None = None,
    insufficient_data: bool = False,
) -> Projection:
    return Projection(
        period_start=_START,
        period_end=_END,
        elapsed_hours=240.0,
        remaining_hours=504.0,
        current_period_spend_cents=current_period_spend_cents,
        burn_rate_cents_per_hour=burn_rate_cents_per_hour,
        projected_period_end_spend_cents=projected_period_end_spend_cents,
        trend_direction=trend_direction,
        insufficient_data=insufficient_data,
    )


def test_insufficient_data_yields_only_that_recommendation():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(current_period_spend_cents=0, insufficient_data=True),
        top_spender=None,
        exhaustion_at=None,
    )
    assert [r.code for r in recs] == ["INSUFFICIENT_DATA"]


def test_no_cost_cap_yields_only_that_recommendation():
    recs = build_recommendations(
        budget=_budget(None),
        projection=_projection(current_period_spend_cents=500_00),
        top_spender=None,
        exhaustion_at=None,
    )
    assert [r.code for r in recs] == ["NO_COST_CAP"]


def test_already_over_cap_is_critical_and_skips_soft_threshold():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(current_period_spend_cents=1200_00),
        top_spender=None,
        exhaustion_at=None,
    )
    codes = [r.code for r in recs]
    assert "ALREADY_OVER_CAP" in codes
    assert "SOFT_THRESHOLD_CROSSED" not in codes
    assert next(r for r in recs if r.code == "ALREADY_OVER_CAP").severity == "critical"


def test_soft_threshold_crossed_when_under_cap_but_over_80_percent():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(current_period_spend_cents=850_00),
        top_spender=None,
        exhaustion_at=None,
    )
    band_rec = next(r for r in recs if r.code == "SOFT_THRESHOLD_CROSSED")
    assert "80%" in band_rec.message
    assert band_rec.severity == "warning"


def test_no_soft_threshold_below_80_percent():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(current_period_spend_cents=500_00),
        top_spender=None,
        exhaustion_at=None,
    )
    assert [r.code for r in recs] == []


def test_projected_to_exceed_with_exhaustion_date_is_warning():
    exhaustion = _START + timedelta(days=15)
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(
            current_period_spend_cents=500_00,
            burn_rate_cents_per_hour=50.0,
            projected_period_end_spend_cents=1500_00,
        ),
        top_spender=None,
        exhaustion_at=exhaustion,
    )
    rec = next(r for r in recs if r.code == "PROJECTED_TO_EXCEED")
    assert rec.severity == "warning"
    assert exhaustion.isoformat() in rec.message


def test_projected_to_exceed_without_exhaustion_date_is_info():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(
            current_period_spend_cents=500_00,
            burn_rate_cents_per_hour=50.0,
            projected_period_end_spend_cents=1500_00,
        ),
        top_spender=None,
        exhaustion_at=None,
    )
    rec = next(r for r in recs if r.code == "PROJECTED_TO_EXCEED")
    assert rec.severity == "info"


def test_no_projected_exceed_when_projection_stays_under_cap():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(
            current_period_spend_cents=500_00,
            burn_rate_cents_per_hour=1.0,
            projected_period_end_spend_cents=600_00,
        ),
        top_spender=None,
        exhaustion_at=None,
    )
    assert "PROJECTED_TO_EXCEED" not in [r.code for r in recs]


def test_rising_trend_adds_informational_recommendation():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(current_period_spend_cents=100_00, trend_direction="rising"),
        top_spender=None,
        exhaustion_at=None,
    )
    rec = next(r for r in recs if r.code == "RISING_TREND")
    assert rec.severity == "info"


def test_flat_or_falling_trend_adds_no_trend_recommendation():
    for direction in ("flat", "falling", None):
        recs = build_recommendations(
            budget=_budget(1000_00),
            projection=_projection(current_period_spend_cents=100_00, trend_direction=direction),
            top_spender=None,
            exhaustion_at=None,
        )
        assert "RISING_TREND" not in [r.code for r in recs]


def test_spend_concentration_flagged_above_50_percent_share():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(current_period_spend_cents=1000_00),
        top_spender=GroupSpendRow(group_key="team-a", cost_cents=600_00, request_count=10),
        exhaustion_at=None,
    )
    rec = next(r for r in recs if r.code == "SPEND_CONCENTRATION")
    assert "team-a" in rec.message
    assert "60%" in rec.message


def test_no_spend_concentration_at_or_below_50_percent_share():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(current_period_spend_cents=1000_00),
        top_spender=GroupSpendRow(group_key="team-a", cost_cents=500_00, request_count=10),
        exhaustion_at=None,
    )
    assert "SPEND_CONCENTRATION" not in [r.code for r in recs]


def test_no_spend_concentration_when_no_top_spender():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(current_period_spend_cents=1000_00),
        top_spender=None,
        exhaustion_at=None,
    )
    assert "SPEND_CONCENTRATION" not in [r.code for r in recs]


def test_multiple_recommendations_can_coexist():
    recs = build_recommendations(
        budget=_budget(1000_00),
        projection=_projection(
            current_period_spend_cents=900_00,
            burn_rate_cents_per_hour=50.0,
            projected_period_end_spend_cents=1500_00,
            trend_direction="rising",
        ),
        top_spender=GroupSpendRow(group_key="agent-x", cost_cents=700_00, request_count=5),
        exhaustion_at=_START + timedelta(days=2),
    )
    codes = {r.code for r in recs}
    assert codes == {
        "SOFT_THRESHOLD_CROSSED",
        "PROJECTED_TO_EXCEED",
        "RISING_TREND",
        "SPEND_CONCENTRATION",
    }
