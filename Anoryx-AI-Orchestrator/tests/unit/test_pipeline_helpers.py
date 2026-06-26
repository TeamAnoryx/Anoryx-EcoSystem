"""Unit tests for the pure pipeline helpers (O-003) — no DB required."""

from __future__ import annotations

from orchestrator.pipeline.ingest_pipeline import (
    _chain_fields,
    _content_hash,
    _extract_common,
)


def test_extract_common_non_dict_payload_all_none():
    out = _extract_common("not-a-dict")
    assert set(out.values()) == {None}
    assert "tenant_id" in out and "event_id" in out


def test_extract_common_non_string_field_is_none():
    out = _extract_common({"tenant_id": "t", "tokens_in": 123, "event_id": None})
    assert out["tenant_id"] == "t"
    assert out["event_id"] is None  # explicit None preserved as None
    # A field that is present but not a string is normalised to None.
    out2 = _extract_common({"event_id": 123})
    assert out2["event_id"] is None


def test_chain_fields_envelope_overrides_payload(make_valid_envelope):
    env = make_valid_envelope()
    payload = dict(env["payload"])
    payload["event_type"] = "some_other_type"  # payload disagrees with envelope
    fields = _chain_fields(env, payload)
    # Envelope-derived classification wins.
    assert fields["event_type"] == env["event_type"]
    assert fields["envelope_id"] == env["envelope_id"]
    assert fields["idempotency_key"] == env["idempotency_key"]
    assert fields["source_product"] == env["source_product"]
    # Payload-derived attribution carried through.
    assert fields["tenant_id"] == payload["tenant_id"]


def test_content_hash_is_stable_and_order_independent():
    a = {"x": 1, "y": 2, "z": [1, 2, 3]}
    b = {"z": [1, 2, 3], "y": 2, "x": 1}  # same content, different key order
    assert _content_hash(a) == _content_hash(b)
    assert len(_content_hash(a)) == 64


def test_content_hash_differs_on_content_change():
    a = {"event_id": "1", "v": 1}
    b = {"event_id": "1", "v": 2}
    assert _content_hash(a) != _content_hash(b)
