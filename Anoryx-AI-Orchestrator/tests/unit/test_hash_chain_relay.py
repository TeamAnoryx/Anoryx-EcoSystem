"""Relay-dispatch hash chain (O-009, ADR-0009): canonicalization + opt-in + tamper.

Pure tests over the relay chain functions in persistence.hash_chain: the opt-in-when-present
rule (a `forwarded` link with no status_code/content_hash/error_reason hashes identically to
one without those keys), tamper-evidence (changing a set field breaks verify), and domain
separation (the relay genesis is distinct from every other chain's genesis).
"""

from __future__ import annotations

import pytest

from orchestrator.persistence import hash_chain as hc


def test_genesis_is_domain_separated() -> None:
    assert hc.RELAY_GENESIS_HASH != hc.GENESIS_HASH
    assert hc.RELAY_GENESIS_HASH != hc.DISTRIBUTION_GENESIS_HASH
    assert hc.RELAY_GENESIS_HASH != hc.REGISTRY_GENESIS_HASH
    assert len(hc.RELAY_GENESIS_HASH) == 64


def test_compute_requires_prev_hash() -> None:
    with pytest.raises(ValueError):
        hc.compute_relay_row_hash({"tenant_id": "t-a", "disposition": "blocked"})


def test_opt_in_absent_fields_hash_identically() -> None:
    base = {
        "tenant_id": "t-a",
        "source_product": "delta",
        "sentinel_id": "s-a",
        "target_path": "/v1/chat/completions",
        "disposition": "blocked",
        "prev_hash": hc.RELAY_GENESIS_HASH,
    }
    with_nones = {**base, "status_code": None, "content_hash": None, "error_reason": None}
    assert hc.compute_relay_row_hash(base) == hc.compute_relay_row_hash(with_nones)


def test_set_optional_field_changes_hash_and_verifies() -> None:
    base = {
        "tenant_id": "t-a",
        "source_product": "delta",
        "sentinel_id": "s-a",
        "target_path": "/v1/chat/completions",
        "disposition": "forwarded",
        "prev_hash": hc.RELAY_GENESIS_HASH,
    }
    with_status = {**base, "status_code": 200}
    h_base = hc.compute_relay_row_hash(base)
    h_status = hc.compute_relay_row_hash(with_status)
    assert h_status != h_base
    assert hc.verify_relay_row_hash(with_status, h_status)


def test_tamper_breaks_verification() -> None:
    row = {
        "tenant_id": "t-a",
        "source_product": "delta",
        "sentinel_id": "s-a",
        "target_path": "/v1/chat/completions",
        "disposition": "blocked",
        "error_reason": "target_unreachable",
        "prev_hash": hc.RELAY_GENESIS_HASH,
    }
    stored = hc.compute_relay_row_hash(row)
    # An attacker rewriting a blocked dispatch to look forwarded breaks the stored hash.
    tampered = {**row, "disposition": "forwarded", "error_reason": None, "status_code": 200}
    assert not hc.verify_relay_row_hash(tampered, stored)


def test_chain_links_via_prev_hash() -> None:
    first = {
        "tenant_id": "t-a",
        "source_product": "delta",
        "sentinel_id": "s-a",
        "target_path": "/v1/chat/completions",
        "disposition": "forwarded",
        "status_code": 200,
        "prev_hash": hc.RELAY_GENESIS_HASH,
    }
    h1 = hc.compute_relay_row_hash(first)
    second = {
        "tenant_id": "t-a",
        "source_product": "rendly",
        "sentinel_id": "s-b",
        "target_path": "/v1/models",
        "disposition": "failed",
        "error_reason": "connect_error",
        "prev_hash": h1,
    }
    h2 = hc.compute_relay_row_hash(second)
    assert h1 != h2
    assert hc.verify_relay_row_hash(second, h2)
