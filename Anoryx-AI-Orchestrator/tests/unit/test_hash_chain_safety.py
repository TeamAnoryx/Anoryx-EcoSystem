"""Safety-event hash chain (X-004): canonicalization + opt-in + tamper.

Pure tests over the safety chain functions in persistence.hash_chain: the opt-in-when-
present rule (a link with no `target` hashes identically to one without the key),
tamper-evidence, and domain separation (the safety genesis is distinct from every other
chain's genesis). Mirrors test_hash_chain_identity.py exactly.
"""

from __future__ import annotations

import pytest

from orchestrator.persistence import hash_chain as hc


def test_genesis_is_domain_separated() -> None:
    assert hc.SAFETY_GENESIS_HASH != hc.GENESIS_HASH
    assert hc.SAFETY_GENESIS_HASH != hc.DISTRIBUTION_GENESIS_HASH
    assert hc.SAFETY_GENESIS_HASH != hc.REGISTRY_GENESIS_HASH
    assert hc.SAFETY_GENESIS_HASH != hc.RELAY_GENESIS_HASH
    assert hc.SAFETY_GENESIS_HASH != hc.IDENTITY_GENESIS_HASH
    assert hc.SAFETY_GENESIS_HASH != hc.AUTOMATION_GENESIS_HASH
    assert hc.SAFETY_GENESIS_HASH != hc.MESSAGING_GENESIS_HASH
    assert hc.SAFETY_GENESIS_HASH != hc.STATE_GENESIS_HASH
    assert hc.SAFETY_GENESIS_HASH != hc.EXTERNAL_GATEWAY_GENESIS_HASH
    assert hc.SAFETY_GENESIS_HASH != hc.ROLLBACK_GENESIS_HASH
    assert len(hc.SAFETY_GENESIS_HASH) == 64


def test_compute_requires_prev_hash() -> None:
    with pytest.raises(ValueError):
        hc.compute_safety_row_hash({"tenant_id": "t-a", "disposition": "accepted"})


def _base_row(**overrides):
    row = {
        "tenant_id": "t-a",
        "source_product": "rendly",
        "category": "pii",
        "outcome": "block",
        "idempotency_key": "rendly-safety-room-7f3a-1",
        "disposition": "accepted",
        "prev_hash": hc.SAFETY_GENESIS_HASH,
    }
    row.update(overrides)
    return row


def test_opt_in_absent_target_hashes_identically() -> None:
    base = _base_row()
    with_none = {**base, "target": None}
    assert hc.compute_safety_row_hash(base) == hc.compute_safety_row_hash(with_none)


def test_set_target_changes_hash_and_verifies() -> None:
    base = _base_row()
    with_target = {**base, "target": "room-7f3a"}
    h_base = hc.compute_safety_row_hash(base)
    h_target = hc.compute_safety_row_hash(with_target)
    assert h_target != h_base
    assert hc.verify_safety_row_hash(with_target, h_target)


def test_tamper_breaks_verification() -> None:
    row = _base_row(disposition="duplicate")
    stored = hc.compute_safety_row_hash(row)
    tampered = {**row, "disposition": "accepted"}
    assert not hc.verify_safety_row_hash(tampered, stored)


def test_chain_links_via_prev_hash() -> None:
    first = _base_row()
    h1 = hc.compute_safety_row_hash(first)
    second = _base_row(
        source_product="sentinel",
        category="injection",
        idempotency_key="sentinel-safety-2",
        disposition="duplicate",
        prev_hash=h1,
    )
    h2 = hc.compute_safety_row_hash(second)
    assert h1 != h2
    assert hc.verify_safety_row_hash(second, h2)
