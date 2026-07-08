"""External-gateway hash chain (O-013, ADR-0013): canonicalization + tamper-evidence.

Pure tests over the external-gateway chain functions in persistence.hash_chain. Like the
messaging chain, EXTERNAL_GATEWAY_CANONICAL_FIELDS has NO opt-in-when-present fields —
every field is always present regardless of outcome (allowed / scope_denied /
rate_limited / revoked), mirroring ADR-0012/ADR-0013's "every attempt" semantics.
"""

from __future__ import annotations

import pytest

from orchestrator.persistence import hash_chain as hc


def test_genesis_is_domain_separated() -> None:
    assert hc.EXTERNAL_GATEWAY_GENESIS_HASH != hc.GENESIS_HASH
    assert hc.EXTERNAL_GATEWAY_GENESIS_HASH != hc.DISTRIBUTION_GENESIS_HASH
    assert hc.EXTERNAL_GATEWAY_GENESIS_HASH != hc.REGISTRY_GENESIS_HASH
    assert hc.EXTERNAL_GATEWAY_GENESIS_HASH != hc.RELAY_GENESIS_HASH
    assert hc.EXTERNAL_GATEWAY_GENESIS_HASH != hc.IDENTITY_GENESIS_HASH
    assert hc.EXTERNAL_GATEWAY_GENESIS_HASH != hc.AUTOMATION_GENESIS_HASH
    assert hc.EXTERNAL_GATEWAY_GENESIS_HASH != hc.MESSAGING_GENESIS_HASH
    assert hc.EXTERNAL_GATEWAY_GENESIS_HASH != hc.STATE_GENESIS_HASH
    assert len(hc.EXTERNAL_GATEWAY_GENESIS_HASH) == 64


def test_compute_requires_prev_hash() -> None:
    with pytest.raises(ValueError):
        hc.compute_external_gateway_row_hash({"tenant_id": "t-a", "outcome": "allowed"})


def _base_row(**overrides):
    row = {
        "tenant_id": "t-a",
        "key_id": "extkey-1",
        "route": "GET /v1/external/events",
        "outcome": "allowed",
        "prev_hash": hc.EXTERNAL_GATEWAY_GENESIS_HASH,
    }
    row.update(overrides)
    return row


@pytest.mark.parametrize("outcome", ["allowed", "scope_denied", "rate_limited", "revoked"])
def test_every_outcome_hashes_and_verifies(outcome) -> None:
    row = _base_row(outcome=outcome)
    h = hc.compute_external_gateway_row_hash(row)
    assert hc.verify_external_gateway_row_hash(row, h)


def test_different_outcomes_hash_differently() -> None:
    allowed = _base_row(outcome="allowed")
    denied = _base_row(outcome="scope_denied")
    assert hc.compute_external_gateway_row_hash(allowed) != hc.compute_external_gateway_row_hash(
        denied
    )


def test_tamper_breaks_verification() -> None:
    row = _base_row()
    stored = hc.compute_external_gateway_row_hash(row)
    tampered = {**row, "outcome": "revoked"}
    assert not hc.verify_external_gateway_row_hash(tampered, stored)


def test_chain_links_via_prev_hash() -> None:
    first = _base_row()
    h1 = hc.compute_external_gateway_row_hash(first)
    second = _base_row(outcome="rate_limited", prev_hash=h1)
    h2 = hc.compute_external_gateway_row_hash(second)
    assert h1 != h2
    assert hc.verify_external_gateway_row_hash(second, h2)


def test_missing_optional_fields_absent_from_canonical_fields() -> None:
    """No opt-in-when-present field exists for this chain — an extra unrelated key in the
    input dict never changes the hash (only EXTERNAL_GATEWAY_CANONICAL_FIELDS members are
    folded in)."""
    base = _base_row()
    with_extra = {**base, "some_unrelated_key": "should be ignored"}
    assert hc.compute_external_gateway_row_hash(base) == hc.compute_external_gateway_row_hash(
        with_extra
    )
