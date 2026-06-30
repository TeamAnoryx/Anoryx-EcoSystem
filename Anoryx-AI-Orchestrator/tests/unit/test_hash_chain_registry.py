"""Registry-mutation hash chain (O-005, ADR-0005): canonicalization + opt-in + tamper.

Pure tests over the registry chain functions in persistence.hash_chain: the opt-in-when-present
rule (an `accepted` link with no endpoint/capabilities/error_reason hashes identically to one
without those keys), tamper-evidence (changing a set field breaks verify), and domain separation
(the registry genesis is distinct from the ingest + distribution genesis).
"""

from __future__ import annotations

import pytest

from orchestrator.persistence import hash_chain as hc


def test_genesis_is_domain_separated() -> None:
    assert hc.REGISTRY_GENESIS_HASH != hc.GENESIS_HASH
    assert hc.REGISTRY_GENESIS_HASH != hc.DISTRIBUTION_GENESIS_HASH
    assert len(hc.REGISTRY_GENESIS_HASH) == 64


def test_compute_requires_prev_hash() -> None:
    with pytest.raises(ValueError):
        hc.compute_registry_row_hash({"sentinel_id": "s", "action": "register"})


def test_opt_in_absent_fields_hash_identically() -> None:
    # A row with the optional fields explicitly None must hash the same as one omitting them.
    base = {
        "sentinel_id": "s-a",
        "action": "register",
        "disposition": "accepted",
        "prev_hash": hc.REGISTRY_GENESIS_HASH,
    }
    with_nones = {**base, "endpoint": None, "capabilities": None, "error_reason": None}
    assert hc.compute_registry_row_hash(base) == hc.compute_registry_row_hash(with_nones)


def test_set_optional_field_changes_hash_and_verifies() -> None:
    base = {
        "sentinel_id": "s-a",
        "action": "register",
        "disposition": "accepted",
        "prev_hash": hc.REGISTRY_GENESIS_HASH,
    }
    with_endpoint = {**base, "endpoint": "https://8.8.8.8"}
    h_base = hc.compute_registry_row_hash(base)
    h_ep = hc.compute_registry_row_hash(with_endpoint)
    assert h_ep != h_base
    assert hc.verify_registry_row_hash(with_endpoint, h_ep)


def test_tamper_breaks_verification() -> None:
    row = {
        "sentinel_id": "s-a",
        "action": "register",
        "disposition": "rejected",
        "endpoint": "https://10.0.0.9",
        "error_reason": "blocked_private_ip",
        "prev_hash": hc.REGISTRY_GENESIS_HASH,
    }
    stored = hc.compute_registry_row_hash(row)
    # An attacker rewriting the rejected endpoint to look accepted breaks the stored hash.
    tampered = {**row, "disposition": "accepted", "error_reason": None}
    assert not hc.verify_registry_row_hash(tampered, stored)


def test_chain_links_via_prev_hash() -> None:
    first = {
        "sentinel_id": "s-a",
        "action": "register",
        "disposition": "accepted",
        "prev_hash": hc.REGISTRY_GENESIS_HASH,
    }
    h1 = hc.compute_registry_row_hash(first)
    second = {
        "sentinel_id": "s-a",
        "action": "deregister",
        "disposition": "accepted",
        "prev_hash": h1,
    }
    h2 = hc.compute_registry_row_hash(second)
    assert h1 != h2
    assert hc.verify_registry_row_hash(second, h2)
