"""Pure automation-rule matcher tests (O-011, ADR-0011). No I/O, no DB.

Covers: event_type match/mismatch, trigger_source_product filter present/absent,
scalar-equality trigger_conditions match/mismatch, a dict/list condition (or payload)
value NEVER matches (and never raises), and empty trigger_conditions always matches
within the same event_type/source_product.
"""

from __future__ import annotations

from orchestrator.automation.matcher import rule_matches


def _rule(**overrides) -> dict:
    base = {
        "trigger_event_type": "policy_decision_deny",
        "trigger_source_product": None,
        "trigger_conditions": {},
    }
    base.update(overrides)
    return base


def test_event_type_mismatch_never_matches():
    rule = _rule(trigger_event_type="policy_decision_deny")
    assert not rule_matches(
        rule, event_type="policy_decision_allow", source_product="sentinel", payload={}
    )


def test_event_type_match_with_empty_conditions_matches():
    rule = _rule()
    assert rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload={"a": 1}
    )


def test_source_product_filter_absent_matches_any_source():
    rule = _rule(trigger_source_product=None)
    assert rule_matches(rule, event_type="policy_decision_deny", source_product="delta", payload={})
    assert rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload={}
    )


def test_source_product_filter_present_and_matching():
    rule = _rule(trigger_source_product="sentinel")
    assert rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload={}
    )


def test_source_product_filter_present_and_mismatching():
    rule = _rule(trigger_source_product="sentinel")
    assert not rule_matches(
        rule, event_type="policy_decision_deny", source_product="delta", payload={}
    )


def test_scalar_condition_matches():
    rule = _rule(trigger_conditions={"violation_type": "budget_cost_exceeded"})
    payload = {"violation_type": "budget_cost_exceeded", "other": 1}
    assert rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload=payload
    )


def test_scalar_condition_mismatch():
    rule = _rule(trigger_conditions={"violation_type": "budget_cost_exceeded"})
    payload = {"violation_type": "prompt_injection"}
    assert not rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload=payload
    )


def test_condition_key_missing_from_payload_never_matches():
    rule = _rule(trigger_conditions={"violation_type": "budget_cost_exceeded"})
    assert not rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload={}
    )


def test_multiple_conditions_all_must_match():
    rule = _rule(
        trigger_conditions={"violation_type": "budget_cost_exceeded", "action_taken": "blocked"}
    )
    payload = {"violation_type": "budget_cost_exceeded", "action_taken": "allowed"}
    assert not rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload=payload
    )


def test_numeric_and_boolean_scalar_conditions_match():
    rule = _rule(trigger_conditions={"count": 3, "flagged": True})
    payload = {"count": 3, "flagged": True}
    assert rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload=payload
    )


def test_dict_condition_value_never_matches_and_never_raises():
    rule = _rule(trigger_conditions={"nested": {"a": 1}})
    payload = {"nested": {"a": 1}}
    assert not rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload=payload
    )


def test_list_condition_value_never_matches_and_never_raises():
    rule = _rule(trigger_conditions={"tags": ["a", "b"]})
    payload = {"tags": ["a", "b"]}
    assert not rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload=payload
    )


def test_dict_payload_value_never_matches_a_scalar_condition():
    # The condition value is a scalar, but the payload's corresponding field is a dict —
    # must never match (and must never raise a TypeError on ==).
    rule = _rule(trigger_conditions={"detail": "blocked"})
    payload = {"detail": {"reason": "blocked"}}
    assert not rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload=payload
    )


def test_none_payload_value_never_matches_a_scalar_condition():
    rule = _rule(trigger_conditions={"detail": "blocked"})
    payload = {"detail": None}
    assert not rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload=payload
    )


def test_non_dict_payload_never_matches_nonempty_conditions_and_never_raises():
    rule = _rule(trigger_conditions={"detail": "blocked"})
    assert not rule_matches(
        rule, event_type="policy_decision_deny", source_product="sentinel", payload="not-a-dict"
    )
