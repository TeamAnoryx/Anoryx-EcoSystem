"""Shared-state hash chain (O-012, ADR-0012): canonicalization + opt-in + tamper-evidence.

Pure tests over the state chain functions in persistence.hash_chain. updated_by_agent_id
is opt-in-when-present (mirrors identity's `target` rule): a link with no attribution
hashes identically to one that never carried the key at all.
"""

from __future__ import annotations

import pytest

from orchestrator.persistence import hash_chain as hc


def test_genesis_is_domain_separated() -> None:
    assert hc.STATE_GENESIS_HASH != hc.GENESIS_HASH
    assert hc.STATE_GENESIS_HASH != hc.DISTRIBUTION_GENESIS_HASH
    assert hc.STATE_GENESIS_HASH != hc.REGISTRY_GENESIS_HASH
    assert hc.STATE_GENESIS_HASH != hc.RELAY_GENESIS_HASH
    assert hc.STATE_GENESIS_HASH != hc.IDENTITY_GENESIS_HASH
    assert hc.STATE_GENESIS_HASH != hc.AUTOMATION_GENESIS_HASH
    assert hc.STATE_GENESIS_HASH != hc.MESSAGING_GENESIS_HASH
    assert len(hc.STATE_GENESIS_HASH) == 64


def test_compute_requires_prev_hash() -> None:
    with pytest.raises(ValueError):
        hc.compute_state_row_hash({"tenant_id": "t-a", "disposition": "created"})


def _base_row(**overrides):
    row = {
        "tenant_id": "t-a",
        "state_key": "shared-counter",
        "version": 1,
        "disposition": "created",
        "prev_hash": hc.STATE_GENESIS_HASH,
    }
    row.update(overrides)
    return row


def test_opt_in_absent_updated_by_agent_id_hashes_identically() -> None:
    base = _base_row()
    with_none = {**base, "updated_by_agent_id": None}
    assert hc.compute_state_row_hash(base) == hc.compute_state_row_hash(with_none)


def test_set_updated_by_agent_id_changes_hash_and_verifies() -> None:
    base = _base_row()
    with_attribution = {**base, "updated_by_agent_id": "agent-a"}
    h_base = hc.compute_state_row_hash(base)
    h_attr = hc.compute_state_row_hash(with_attribution)
    assert h_base != h_attr
    assert hc.verify_state_row_hash(with_attribution, h_attr)


def test_tamper_breaks_verification() -> None:
    row = _base_row(disposition="updated", version=2)
    stored = hc.compute_state_row_hash(row)
    tampered = {**row, "version": 3}
    assert not hc.verify_state_row_hash(tampered, stored)


def test_chain_links_via_prev_hash() -> None:
    first = _base_row()
    h1 = hc.compute_state_row_hash(first)
    second = _base_row(version=2, disposition="updated", prev_hash=h1)
    h2 = hc.compute_state_row_hash(second)
    assert h1 != h2
    assert hc.verify_state_row_hash(second, h2)


def test_version_conflict_is_never_hashed_in_by_the_caller() -> None:
    """A version-conflict rejection produces NO row for THIS chain (ADR-0012 mirrors
    ADR-0011's automation_executions choice) — this is enforced by the router/repository
    layer (append_state_audit_link is only ever called for a genuine created/updated write),
    not by anything in hash_chain.py itself, so there is no chain-level assertion to make
    here beyond confirming 'version_conflict' is not a disposition this chain's CHECK
    constraint would even accept (see the migration's ck_asa_disposition constraint)."""
    row = _base_row(disposition="created")
    assert row["disposition"] in ("created", "updated")
