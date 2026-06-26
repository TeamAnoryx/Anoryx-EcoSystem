"""Unit tests for the two-stage schema validation (O-003)."""

from __future__ import annotations

from orchestrator.schema_validation import envelope_structure_errors, payload_errors


def test_valid_envelope_passes_structure(make_valid_envelope):
    assert envelope_structure_errors(make_valid_envelope()) == []


def test_valid_payload_passes_events_schema(make_valid_envelope):
    assert payload_errors(make_valid_envelope()["payload"]) == []


def test_missing_required_envelope_field_fails_structure(make_valid_envelope):
    env = make_valid_envelope()
    del env["sequence"]  # required envelope field
    assert envelope_structure_errors(env) != []


def test_non_integer_schema_version_fails_structure(make_valid_envelope):
    env = make_valid_envelope()
    env["schema_version"] = "1"  # string, not int
    assert envelope_structure_errors(env) != []


def test_unknown_schema_version_still_passes_structure(make_valid_envelope):
    # ADR-0002 Fork C: an unknown version is STRUCTURALLY valid (int) so it reaches the
    # pipeline → DLQ, NOT a 422. The structural gate must accept it.
    env = make_valid_envelope()
    env["schema_version"] = 2
    assert envelope_structure_errors(env) == []


def test_structure_does_not_deep_validate_payload(make_valid_envelope):
    # The shallow envelope check treats payload as a generic object — a broken payload is
    # NOT caught here (it is caught in the pipeline → DLQ payload_schema_invalid).
    env = make_valid_envelope()
    env["payload"] = {"event_type": "policy_decision_deny"}  # missing required fields
    assert envelope_structure_errors(env) == []


def test_invalid_payload_fails_events_schema(make_valid_envelope):
    env = make_valid_envelope()
    env["payload"].pop("tenant_id")  # a required stable ID
    assert payload_errors(env["payload"]) != []


def test_payload_with_bad_uuid_fails_format(make_valid_envelope):
    env = make_valid_envelope()
    env["payload"]["tenant_id"] = "not-a-uuid"
    assert payload_errors(env["payload"]) != []
