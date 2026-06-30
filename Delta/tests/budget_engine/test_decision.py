"""Pure decision logic: integer boundary, no float (ADR-0005 §3.3, vectors 3+4)."""

from __future__ import annotations

from delta.budget import BudgetPeriod, BudgetScope
from delta.budget_engine.decision import is_over_cost_cap, soft_warning_band
from delta.budget_engine.definitions import BudgetDefinition


def _budget(limit_cost_cents: int | None) -> BudgetDefinition:
    return BudgetDefinition(
        budget_id="b",
        tenant_id="11111111-1111-4111-8111-111111111111",
        scope=BudgetScope.TENANT,
        team_id="22222222-2222-4222-8222-222222222222",
        project_id="33333333-3333-4333-8333-333333333333",
        agent_id="gateway-core",
        period=BudgetPeriod.DAILY,
        limit_tokens=None,
        limit_cost_cents=limit_cost_cents,
        currency="USD",
        policy_id="44444444-4444-4444-8444-444444444444",
    )


def test_at_cap_is_not_over():
    # spend == cap is within budget; only strictly-greater is over.
    assert is_over_cost_cap(1000, _budget(1000)) is False


def test_one_cent_over_is_over():
    assert is_over_cost_cap(1001, _budget(1000)) is True


def test_under_cap_is_not_over():
    assert is_over_cost_cap(999, _budget(1000)) is False


def test_no_cost_cap_never_over():
    assert is_over_cost_cap(10**12, _budget(None)) is False


def test_zero_cap_any_spend_over():
    assert is_over_cost_cap(1, _budget(0)) is True
    assert is_over_cost_cap(0, _budget(0)) is False


def test_decision_inputs_are_integers_no_float():
    # A guard that the comparison operands are ints (a float would risk a boundary flip).
    b = _budget(1000)
    assert isinstance(b.limit_cost_cents, int)
    assert is_over_cost_cap(1000, b) is False and is_over_cost_cap(1001, b) is True


def test_soft_warning_band_integer_thresholds():
    pcts = (80, 95)
    b = _budget(1000)
    assert soft_warning_band(799, b, pcts) is None  # below 80%
    assert soft_warning_band(800, b, pcts) == 80  # exactly 80%
    assert soft_warning_band(949, b, pcts) == 80
    assert soft_warning_band(950, b, pcts) == 95  # exactly 95%
    assert soft_warning_band(999, b, pcts) == 95


def test_soft_warning_band_at_cap_returns_band_over_cap_none():
    # spend == cap is within budget (not over) -> highest band; spend > cap -> None (the
    # strict-> enforcement boundary, matching is_over_cost_cap).
    b = _budget(1000)
    assert soft_warning_band(1000, b, (80, 95)) == 95  # at cap: within budget -> warn band
    assert soft_warning_band(1001, b, (80, 95)) is None  # over cap -> enforcement, no warning


def test_soft_warning_band_no_cap_or_zero_cap_none():
    assert soft_warning_band(500, _budget(None), (80, 95)) is None
    assert soft_warning_band(500, _budget(0), (80, 95)) is None
