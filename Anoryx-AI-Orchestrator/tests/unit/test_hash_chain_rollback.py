"""Distribution-rollback correlation hash chain (O-014, ADR-0014): canonicalization +
tamper-evidence.

Pure tests over the rollback chain functions in persistence.hash_chain. Every rollback is
an operator-triggered action — there is no rejected/no-op case, so (unlike the messaging
or state chains) there is only one "shape" of row, no disposition/outcome field to vary.
"""

from __future__ import annotations

import pytest

from orchestrator.persistence import hash_chain as hc


def test_genesis_is_domain_separated() -> None:
    assert hc.ROLLBACK_GENESIS_HASH != hc.GENESIS_HASH
    assert hc.ROLLBACK_GENESIS_HASH != hc.DISTRIBUTION_GENESIS_HASH
    assert hc.ROLLBACK_GENESIS_HASH != hc.REGISTRY_GENESIS_HASH
    assert hc.ROLLBACK_GENESIS_HASH != hc.RELAY_GENESIS_HASH
    assert hc.ROLLBACK_GENESIS_HASH != hc.IDENTITY_GENESIS_HASH
    assert hc.ROLLBACK_GENESIS_HASH != hc.AUTOMATION_GENESIS_HASH
    assert hc.ROLLBACK_GENESIS_HASH != hc.MESSAGING_GENESIS_HASH
    assert hc.ROLLBACK_GENESIS_HASH != hc.STATE_GENESIS_HASH
    assert hc.ROLLBACK_GENESIS_HASH != hc.EXTERNAL_GATEWAY_GENESIS_HASH
    assert len(hc.ROLLBACK_GENESIS_HASH) == 64


def test_compute_requires_prev_hash() -> None:
    with pytest.raises(ValueError):
        hc.compute_rollback_row_hash({"tenant_id": "t-a", "policy_id": "p-1"})


def _base_row(**overrides):
    row = {
        "tenant_id": "t-a",
        "policy_id": "p-1",
        "source_distribution_id": "dist-old",
        "superseded_distribution_id": "dist-current",
        "new_distribution_id": "dist-new",
        "prev_hash": hc.ROLLBACK_GENESIS_HASH,
    }
    row.update(overrides)
    return row


def test_hashes_and_verifies() -> None:
    row = _base_row()
    h = hc.compute_rollback_row_hash(row)
    assert hc.verify_rollback_row_hash(row, h)
    assert len(h) == 64


def test_tamper_breaks_verification() -> None:
    row = _base_row()
    stored = hc.compute_rollback_row_hash(row)
    tampered = {**row, "new_distribution_id": "dist-substituted"}
    assert not hc.verify_rollback_row_hash(tampered, stored)


def test_chain_links_via_prev_hash() -> None:
    first = _base_row()
    h1 = hc.compute_rollback_row_hash(first)
    second = _base_row(new_distribution_id="dist-new-2", prev_hash=h1)
    h2 = hc.compute_rollback_row_hash(second)
    assert h1 != h2
    assert hc.verify_rollback_row_hash(second, h2)


def test_missing_optional_fields_absent_from_canonical_fields() -> None:
    """No opt-in-when-present field exists for this chain — an extra unrelated key in the
    input dict never changes the hash."""
    base = _base_row()
    with_extra = {**base, "some_unrelated_key": "should be ignored"}
    assert hc.compute_rollback_row_hash(base) == hc.compute_rollback_row_hash(with_extra)
