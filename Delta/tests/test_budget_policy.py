"""BudgetPolicy / BudgetWarningTier behavior (D-002, ADR-0002).

Type-level invariants: the XOR threshold basis, the homogeneous-basis +
strictly-ascending + below-cap warning soundness rules (Fork 1), envelope bounds,
and a lossless Pydantic round-trip. Emit/serialization is proven separately in
``test_budget_policy_emit.py``; wrapper-schema conformance in
``test_budget_policy_schema.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope
from delta.budget_policy import (
    MAX_POLICY_VERSION,
    BudgetPolicy,
    BudgetWarningTier,
    WarningAction,
)

_T = "12121212-1212-4212-8212-121212121212"
_TEAM = "13131313-1313-4313-8313-131313131313"
_PROJ = "14141414-1414-4414-8414-141414141414"
_POLICY = "1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a"
_EFF = datetime(2026, 6, 26, 0, 0, 0, tzinfo=timezone.utc)


def _cap(**over) -> BudgetConcept:
    base = dict(
        tenant_id=_T,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="gateway-core",
        scope=BudgetScope.TEAM,
        period=BudgetPeriod.MONTHLY,
        limit_cost_cents=500_000,
    )
    base.update(over)
    return BudgetConcept(**base)


def _policy(**over) -> BudgetPolicy:
    base = dict(
        cap=_cap(),
        policy_id=_POLICY,
        policy_version=1,
        effective_from=_EFF,
    )
    base.update(over)
    return BudgetPolicy(**base)


def _pct(p: int, action: WarningAction = WarningAction.NOTIFY) -> BudgetWarningTier:
    return BudgetWarningTier(threshold_percent=p, action=action)


def _abs(c: int, action: WarningAction = WarningAction.ALERT) -> BudgetWarningTier:
    return BudgetWarningTier(threshold_cost_cents=c, action=action)


# --- happy paths ---------------------------------------------------------------
def test_policy_with_no_warnings_is_valid():
    p = _policy(warnings=())
    assert p.warnings == ()


def test_percent_warnings_ascending_valid():
    p = _policy(warnings=(_pct(50), _pct(80), _pct(95, WarningAction.PAGE)))
    assert tuple(w.basis for w in p.warnings) == ("percent", "percent", "percent")


def test_absolute_warnings_ascending_valid():
    # cap is 500_000 cents; tiers strictly below it and ascending.
    p = _policy(warnings=(_abs(100_000), _abs(400_000)))
    assert tuple(w.order_value for w in p.warnings) == (100_000, 400_000)


def test_warnings_default_to_empty_tuple():
    assert _policy().warnings == ()


# --- XOR basis at the tier ------------------------------------------------------
def test_tier_requires_exactly_one_basis_neither():
    with pytest.raises(ValidationError):
        BudgetWarningTier(action=WarningAction.NOTIFY)


def test_tier_requires_exactly_one_basis_both():
    with pytest.raises(ValidationError):
        BudgetWarningTier(
            threshold_percent=50, threshold_cost_cents=100, action=WarningAction.NOTIFY
        )


def test_explicit_none_for_unused_basis_is_accepted():
    # Passing the unused basis as an explicit None (not just omitting it) still
    # satisfies the XOR — the before-validators' None guard accepts it.
    absolute = BudgetWarningTier(
        threshold_percent=None, threshold_cost_cents=400_000, action=WarningAction.ALERT
    )
    percent = BudgetWarningTier(
        threshold_percent=50, threshold_cost_cents=None, action=WarningAction.NOTIFY
    )
    assert absolute.basis == "absolute"
    assert percent.basis == "percent"


@pytest.mark.parametrize("bad", [0, 100, 101, -1])
def test_percent_out_of_range_rejected(bad):
    with pytest.raises(ValidationError):
        BudgetWarningTier(threshold_percent=bad, action=WarningAction.NOTIFY)


def test_percent_float_rejected():
    with pytest.raises(ValidationError):
        BudgetWarningTier(threshold_percent=50.0, action=WarningAction.NOTIFY)


def test_absolute_zero_rejected():
    with pytest.raises(ValidationError):
        BudgetWarningTier(threshold_cost_cents=0, action=WarningAction.ALERT)


def test_absolute_float_rejected():
    with pytest.raises(ValidationError):
        BudgetWarningTier(threshold_cost_cents=1.5, action=WarningAction.ALERT)


# --- warning soundness at the policy -------------------------------------------
def test_mixed_basis_rejected():
    with pytest.raises(ValidationError, match="one basis"):
        _policy(warnings=(_pct(50), _abs(400_000)))


def test_unordered_percent_rejected():
    with pytest.raises(ValidationError, match="ascending"):
        _policy(warnings=(_pct(80), _pct(50)))


def test_duplicate_percent_rejected():
    with pytest.raises(ValidationError, match="ascending"):
        _policy(warnings=(_pct(50), _pct(50)))


def test_unordered_absolute_rejected():
    with pytest.raises(ValidationError, match="ascending"):
        _policy(warnings=(_abs(400_000), _abs(100_000)))


def test_absolute_at_cap_rejected():
    # threshold == cap is not strictly below -> over-permissive.
    with pytest.raises(ValidationError, match="< cap.limit_cost_cents"):
        _policy(warnings=(_abs(500_000),))


def test_absolute_above_cap_rejected():
    with pytest.raises(ValidationError, match="< cap.limit_cost_cents"):
        _policy(warnings=(_abs(600_000),))


def test_absolute_warning_requires_cost_cap():
    # token-only cap has no limit_cost_cents -> an absolute tier is meaningless.
    token_cap = _cap(limit_tokens=1000, limit_cost_cents=None)
    with pytest.raises(ValidationError, match="limit_cost_cents"):
        _policy(cap=token_cap, warnings=(_abs(100_000),))


def test_percent_warning_ok_on_token_only_cap():
    token_cap = _cap(limit_tokens=1000, limit_cost_cents=None)
    p = _policy(cap=token_cap, warnings=(_pct(80),))
    assert p.warnings[0].basis == "percent"


# --- over-permissive cap is rejected before a policy can wrap it ----------------
def test_cap_with_no_limit_cannot_be_built():
    # BudgetConcept enforces at-least-one-of; an empty cap never constructs, so no
    # BudgetPolicy can wrap a limit-nothing cap.
    with pytest.raises(ValidationError):
        _cap(limit_tokens=None, limit_cost_cents=None)


# --- envelope bounds -----------------------------------------------------------
@pytest.mark.parametrize("bad", [0, -1])
def test_policy_version_below_one_rejected(bad):
    with pytest.raises(ValidationError):
        _policy(policy_version=bad)


def test_policy_version_float_rejected():
    with pytest.raises(ValidationError):
        _policy(policy_version=1.0)


def test_policy_version_max_ok():
    assert _policy(policy_version=MAX_POLICY_VERSION).policy_version == MAX_POLICY_VERSION


def test_policy_version_over_max_rejected():
    with pytest.raises(ValidationError):
        _policy(policy_version=MAX_POLICY_VERSION + 1)


def test_naive_effective_from_rejected():
    with pytest.raises(ValidationError, match="timezone-aware"):
        _policy(effective_from=datetime(2026, 6, 26, 0, 0, 0))


def test_bad_policy_id_rejected():
    # UuidStr enforces the canonical dashed-UUID format on the envelope id.
    with pytest.raises(ValidationError):
        _policy(policy_id="not-a-uuid")


def test_frozen_policy_is_immutable():
    p = _policy()
    with pytest.raises(ValidationError):
        p.policy_version = 2


# --- lossless round-trip -------------------------------------------------------
def test_pydantic_json_roundtrip_lossless():
    p = _policy(warnings=(_pct(50), _pct(90, WarningAction.PAGE)))
    restored = BudgetPolicy.model_validate(p.model_dump(mode="json"))
    assert restored == p


def test_warnings_stay_a_tuple_not_a_list():
    # H-1: a frozen model must not expose a mutable list for deep immutability.
    p = _policy(warnings=(_pct(50),))
    assert isinstance(p.warnings, tuple)
