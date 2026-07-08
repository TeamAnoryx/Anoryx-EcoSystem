"""Automation-execution hash chain (O-011, ADR-0011): canonicalization + opt-in + tamper.

Mirrors test_hash_chain_relay.py / test_hash_chain_identity.py: the opt-in-when-present
rule (an `executed` link with no error_reason hashes identically to one without the key),
tamper-evidence (changing a set field breaks verify), and domain separation (the
automation genesis is distinct from every other chain's genesis).
"""

from __future__ import annotations

import pytest

from orchestrator.persistence import hash_chain as hc


def test_genesis_is_domain_separated() -> None:
    assert hc.AUTOMATION_GENESIS_HASH != hc.GENESIS_HASH
    assert hc.AUTOMATION_GENESIS_HASH != hc.DISTRIBUTION_GENESIS_HASH
    assert hc.AUTOMATION_GENESIS_HASH != hc.REGISTRY_GENESIS_HASH
    assert hc.AUTOMATION_GENESIS_HASH != hc.RELAY_GENESIS_HASH
    assert hc.AUTOMATION_GENESIS_HASH != hc.IDENTITY_GENESIS_HASH
    assert len(hc.AUTOMATION_GENESIS_HASH) == 64


def test_compute_requires_prev_hash() -> None:
    with pytest.raises(ValueError):
        hc.compute_automation_row_hash({"rule_id": "rule-a", "disposition": "executed"})


def test_opt_in_absent_error_reason_hashes_identically() -> None:
    base = {
        "rule_id": "rule-a",
        "tenant_id": "t-a",
        "triggering_event_id": "evt-a",
        "action_type": "redistribute_policy",
        "disposition": "executed",
        "prev_hash": hc.AUTOMATION_GENESIS_HASH,
    }
    with_none = {**base, "error_reason": None}
    assert hc.compute_automation_row_hash(base) == hc.compute_automation_row_hash(with_none)


def test_set_error_reason_changes_hash_and_verifies() -> None:
    base = {
        "rule_id": "rule-a",
        "tenant_id": "t-a",
        "triggering_event_id": "evt-a",
        "action_type": "redistribute_policy",
        "disposition": "failed",
        "prev_hash": hc.AUTOMATION_GENESIS_HASH,
    }
    with_reason = {**base, "error_reason": "distribution_not_found"}
    h_base = hc.compute_automation_row_hash(base)
    h_reason = hc.compute_automation_row_hash(with_reason)
    assert h_reason != h_base
    assert hc.verify_automation_row_hash(with_reason, h_reason)


def test_tamper_breaks_verification() -> None:
    row = {
        "rule_id": "rule-a",
        "tenant_id": "t-a",
        "triggering_event_id": "evt-a",
        "action_type": "redistribute_policy",
        "disposition": "failed",
        "error_reason": "distribution_not_found",
        "prev_hash": hc.AUTOMATION_GENESIS_HASH,
    }
    stored = hc.compute_automation_row_hash(row)
    # An attacker rewriting a failed execution to look executed breaks the stored hash.
    tampered = {**row, "disposition": "executed", "error_reason": None}
    assert not hc.verify_automation_row_hash(tampered, stored)


def test_chain_links_via_prev_hash() -> None:
    first = {
        "rule_id": "rule-a",
        "tenant_id": "t-a",
        "triggering_event_id": "evt-a",
        "action_type": "redistribute_policy",
        "disposition": "executed",
        "prev_hash": hc.AUTOMATION_GENESIS_HASH,
    }
    h1 = hc.compute_automation_row_hash(first)
    second = {
        "rule_id": "rule-b",
        "tenant_id": "t-a",
        "triggering_event_id": "evt-b",
        "action_type": "redistribute_policy",
        "disposition": "failed",
        "error_reason": "redistribute_policy_error",
        "prev_hash": h1,
    }
    h2 = hc.compute_automation_row_hash(second)
    assert h1 != h2
    assert hc.verify_automation_row_hash(second, h2)
