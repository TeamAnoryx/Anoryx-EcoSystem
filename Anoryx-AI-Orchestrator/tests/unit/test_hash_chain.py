"""Unit tests for the ingest-audit hash chain (O-003)."""

from __future__ import annotations

from orchestrator.persistence import hash_chain


def _row(**overrides):
    base = {
        "event_id": "c1d2e3f4-5678-4abc-9def-0123456789ab",
        "event_type": "policy_decision_deny",
        "event_timestamp": "2026-06-26T12:00:00Z",
        "request_id": "req-1",
        "tenant_id": "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6",
        "team_id": "7d9e2f3a-1234-5c6b-8def-0123456789ab",
        "project_id": "b3c4d5e6-abcd-1234-ef01-234567890abc",
        "agent_id": "gateway-core",
        "envelope_id": "f0e1d2c3-4b5a-4c6d-8e9f-0a1b2c3d4e5f",
        "idempotency_key": "c1d2e3f4-5678-4abc-9def-0123456789ab",
        "source_product": "sentinel",
        "disposition": "accepted",
        "prev_hash": hash_chain.GENESIS_HASH,
    }
    base.update(overrides)
    return base


def test_genesis_is_distinct_and_stable():
    assert len(hash_chain.GENESIS_HASH) == 64
    # Distinct from Sentinel's genesis (different domain-separation string).
    import hashlib

    assert (
        hash_chain.GENESIS_HASH != hashlib.sha256(b"anoryx-sentinel:events:genesis:v1").hexdigest()
    )


def test_compute_and_verify_round_trip():
    row = _row()
    h = hash_chain.compute_row_hash(row)
    assert len(h) == 64
    assert hash_chain.verify_row_hash(row, h) is True


def test_tamper_breaks_verification():
    row = _row()
    h = hash_chain.compute_row_hash(row)
    tampered = _row(tenant_id="00000000-0000-0000-0000-000000000000")
    assert hash_chain.verify_row_hash(tampered, h) is False


def test_opt_in_when_present_accepted_row_identical_without_dlq_fields():
    # An accepted row (no dlq_reason/dlq_id) hashes identically whether the keys are
    # absent or explicitly None — backward-compatible by construction.
    absent = _row()
    explicit_none = _row(dlq_reason=None, dlq_id=None)
    assert hash_chain.compute_row_hash(absent) == hash_chain.compute_row_hash(explicit_none)


def test_dlq_fields_are_bound_when_present():
    base = hash_chain.compute_row_hash(_row(disposition="dead_lettered"))
    with_reason = hash_chain.compute_row_hash(
        _row(disposition="dead_lettered", dlq_reason="unknown_schema_version")
    )
    assert base != with_reason


def test_missing_required_field_raises():
    row = _row()
    del row["prev_hash"]
    try:
        hash_chain.compute_row_hash(row)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
