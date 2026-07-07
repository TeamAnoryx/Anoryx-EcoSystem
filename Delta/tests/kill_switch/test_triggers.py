"""Pure kill-switch trigger logic — no I/O, no DB (ADR-0006 §3.1, vector 9)."""

from __future__ import annotations

from delta.kill_switch.triggers import (
    ANOMALOUS_SINGLE_TX,
    UNAUTHORIZED_AGENT,
    anomalous_reason,
    detect_reason,
    unauthorized_reason,
)


def test_ungated_tenant_never_triggers_unauthorized():
    # vector 9: zero allow-list rows (not gated) means the identity trigger is INERT,
    # regardless of whether this particular agent happens to be "authorized".
    assert unauthorized_reason(gated=False, authorized=False) is None
    assert unauthorized_reason(gated=False, authorized=True) is None


def test_gated_tenant_unauthorized_agent_triggers():
    assert unauthorized_reason(gated=True, authorized=False) == UNAUTHORIZED_AGENT


def test_gated_tenant_authorized_agent_does_not_trigger():
    assert unauthorized_reason(gated=True, authorized=True) is None


def test_anomalous_disabled_by_default():
    # No ceiling configured -> inert regardless of cost.
    assert anomalous_reason(cost_cents=10_000_000, max_single_tx_cost_cents=None) is None


def test_anomalous_strictly_greater_than_ceiling():
    assert anomalous_reason(cost_cents=1000, max_single_tx_cost_cents=1000) is None  # ==, not over
    assert anomalous_reason(cost_cents=1001, max_single_tx_cost_cents=1000) == ANOMALOUS_SINGLE_TX
    assert anomalous_reason(cost_cents=999, max_single_tx_cost_cents=1000) is None


def test_detect_reason_unauthorized_checked_before_anomalous():
    reason = detect_reason(gated=True, authorized=False, cost_cents=5, max_single_tx_cost_cents=1)
    assert reason == UNAUTHORIZED_AGENT


def test_detect_reason_falls_through_to_anomalous():
    reason = detect_reason(
        gated=True, authorized=True, cost_cents=5000, max_single_tx_cost_cents=1000
    )
    assert reason == ANOMALOUS_SINGLE_TX


def test_detect_reason_none_when_neither_triggers():
    reason = detect_reason(gated=True, authorized=True, cost_cents=5, max_single_tx_cost_cents=1000)
    assert reason is None
