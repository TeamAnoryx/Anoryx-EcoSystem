"""Conformance: Delta's vendored signer is byte-identical to Sentinel's verifier.

The vendored ``delta.policy.sign`` MUST reproduce Sentinel ``policy.crypto`` exactly, or a
Delta-signed policy is rejected at intake. ECDSA is non-deterministic, so the signature
STRING cannot be compared — instead this asserts the deterministic primitives byte-for-byte
(claim set, header, canonicalization, content hash, claim extraction) and proves a Delta
signature VERIFIES through Sentinel's real ``verify_compact_jws``. If Sentinel's
canonicalization migrates to JCS (ADR-0009 §12.1), this test breaks and the vendored copy
must follow.

Imports Sentinel's ``policy`` package from ``Anoryx-Sentinel/src`` (a test-only cross-
product dependency; the CI lane installs it). Skips cleanly if it is not importable. This
test lives under ``tests/budget_engine`` (not ``tests/policy``) on purpose: a ``tests/policy``
package would shadow Sentinel's top-level ``policy`` package and break the import.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from delta.policy import sign as dsign

# Make Sentinel's `policy` package importable from the sibling subproject.
_SENTINEL_SRC = Path(__file__).resolve().parents[3] / "Anoryx-Sentinel" / "src"
if _SENTINEL_SRC.is_dir() and str(_SENTINEL_SRC) not in sys.path:
    sys.path.insert(0, str(_SENTINEL_SRC))

crypto = pytest.importorskip("policy.crypto", reason="Sentinel policy.crypto not importable")
constants = pytest.importorskip("policy.constants")


def _budget_record() -> dict:
    """A budget_limit record shaped like the D-002 emit output (8 claims + body fields)."""
    return {
        "policy_type": "budget_limit",
        "tenant_id": "11111111-1111-4111-8111-111111111111",
        "team_id": "22222222-2222-4222-8222-222222222222",
        "project_id": "33333333-3333-4333-8333-333333333333",
        "agent_id": "gateway-core",
        "policy_id": "44444444-4444-4444-8444-444444444444",
        "policy_version": 7,
        "effective_from": "2026-07-01T00:00:00Z",
        "signature": "AAAAAAAAAAAA.BBBBBBBBBBBB.CCCCCCCCCCCC",  # placeholder, ignored by hash
        "period": "daily",
        "scope": "team",
        "max_cost_cents_per_period": 500000,
    }


def test_claim_field_set_matches_sentinel():
    assert dsign.SIGNED_CLAIM_FIELDS == constants.SIGNED_CLAIM_FIELDS
    assert dsign.CONTENT_HASH_CLAIM == constants.CONTENT_HASH_CLAIM


def test_header_bytes_match():
    assert dsign._encode_header() == crypto._encode_header()


def test_canonical_claims_match_including_non_ascii():
    # Non-ASCII proves ensure_ascii (\\uXXXX escaping) agreement, not just key ordering.
    sample = {"z": 1, "a": "café", "m": ["x", "y"], "n": 12345}
    assert dsign.canonical_claims(sample) == crypto.canonical_claims(sample)


def test_content_hash_matches():
    record = _budget_record()
    assert dsign.policy_content_hash(record) == crypto.policy_content_hash(record)


def test_extract_claims_matches():
    record = _budget_record()
    assert dsign.extract_claims(record) == crypto.extract_claims(record)


def test_delta_signature_verifies_with_sentinel_verifier():
    """A Delta-signed record's signature is accepted by Sentinel's real verifier, and the
    recovered claims equal the eight scope claims + the content hash."""
    private_key, public_key = crypto.generate_keypair()
    record = _budget_record()
    signed = dsign.sign_policy_record(record, private_key)

    claims = crypto.verify_compact_jws(signed["signature"], public_key)  # raises on failure

    expected = dict(crypto.extract_claims(record))
    expected[constants.CONTENT_HASH_CLAIM] = crypto.policy_content_hash(record)
    assert claims == expected


def test_tampering_a_body_field_breaks_the_content_hash():
    """The content hash binds the whole record: a post-sign body edit fails verification."""
    private_key, public_key = crypto.generate_keypair()
    record = _budget_record()
    signed = dsign.sign_policy_record(record, private_key)

    claims = crypto.verify_compact_jws(signed["signature"], public_key)
    tampered = dict(signed)
    tampered["max_cost_cents_per_period"] = 1  # widen/narrow the cap after signing
    assert crypto.policy_content_hash(tampered) != claims[constants.CONTENT_HASH_CLAIM]


def test_refuses_to_sign_wildcard_tenant():
    private_key, _ = crypto.generate_keypair()
    record = _budget_record()
    record["tenant_id"] = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(dsign.PolicySignError):
        dsign.sign_policy_record(record, private_key)
