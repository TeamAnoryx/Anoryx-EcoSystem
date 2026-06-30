"""Unit tests for the two-stage schema validation (O-003)."""

from __future__ import annotations

import uuid

from orchestrator.schema_validation import (
    envelope_structure_errors,
    payload_errors,
    policy_schema_errors,
)


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


# --------------------------------------------------------------------------- #
# policy_schema_errors — the O-004 distribution seam's locked policy.schema.json
# validation, exercised directly (no router, no DB).
# --------------------------------------------------------------------------- #


def _valid_signed_policy() -> dict:
    """A schema-valid model_denylist policy with a well-formed (unverified) signature.

    policy_schema_errors only STRUCTURALLY validates against the locked sentinel:policy:v1
    schema (it never verifies the JWS), so a syntactically valid signature is sufficient.
    """
    return {
        "policy_type": "model_denylist",
        "tenant_id": str(uuid.uuid4()),
        "team_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "agent_id": "gateway-core",
        "policy_id": str(uuid.uuid4()),
        "policy_version": 1,
        "effective_from": "2026-01-01T00:00:00Z",
        "signature": "aaaaaa.bbbbbb.cccccc",
        "denied_model_ids": ["gpt-3.5-turbo"],
        "reason": "unit test policy",
    }


def test_valid_policy_passes_locked_schema():
    assert policy_schema_errors(_valid_signed_policy()) == []


def test_incomplete_policy_fails_locked_schema():
    # Only policy_type present → the locked sentinel:policy:v1 oneOf has no satisfiable variant.
    assert policy_schema_errors({"policy_type": "model_allowlist"}) != []


def test_locked_policy_schema_id_is_v1():
    from orchestrator.schema_validation import _policy_validator

    assert _policy_validator().schema["$id"] == "sentinel:policy:v1"
