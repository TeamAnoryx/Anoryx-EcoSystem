"""Contract conformance: every F-008 event we EMIT validates against
contracts/events.schema.json (ADR-0009 §7, 4-site consistency).

This is the bus-contract side of the 4-site check. The other three sites
(VALID_EVENT_TYPES, ACTION_TAKEN_BY_EVENT_TYPE, the ck_eal_event_type CHECK) are
exercised by the intake/variant tests that actually append these events to the
audit log.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from policy.audit_events import build_policy_event, system_scope
from policy.constants import (
    EVT_DECISION_ALLOW,
    EVT_DECISION_DENY,
    EVT_INTAKE_ACCEPTED,
    EVT_INTAKE_REJECTED_REPLAY,
    EVT_INTAKE_REJECTED_SCHEMA,
    EVT_INTAKE_REJECTED_SCOPE_MISMATCH,
    EVT_INTAKE_REJECTED_SIGNATURE,
    POLICY_EVENT_TYPES,
)

_EVENTS_SCHEMA_PATH = Path(__file__).parents[2] / "contracts" / "events.schema.json"


def _schema() -> dict:
    with open(_EVENTS_SCHEMA_PATH, "rb") as fh:
        return json.load(fh)


def _real_scope() -> dict[str, str]:
    return {
        "tenant_id": str(uuid.uuid4()),
        "team_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "agent_id": "gateway-core",
    }


def test_events_schema_is_valid_draft202012():
    Draft202012Validator.check_schema(_schema())


def test_all_seven_variants_present_in_oneof():
    schema = _schema()
    refs = {entry["$ref"].split("/")[-1] for entry in schema["oneOf"]}
    for name in (
        "PolicyIntakeAcceptedEvent",
        "PolicyIntakeRejectedSignatureEvent",
        "PolicyIntakeRejectedScopeMismatchEvent",
        "PolicyIntakeRejectedReplayEvent",
        "PolicyIntakeRejectedSchemaEvent",
        "PolicyDecisionAllowEvent",
        "PolicyDecisionDenyEvent",
    ):
        assert name in refs, f"{name} missing from oneOf"
        assert name in schema["$defs"], f"{name} missing from $defs"


def _emitted_samples() -> dict[str, dict]:
    """One representative emitted event per F-008 variant (shapes match intake/enforcement)."""
    pid = str(uuid.uuid4())
    return {
        EVT_INTAKE_ACCEPTED: build_policy_event(
            EVT_INTAKE_ACCEPTED,
            scope=_real_scope(),
            request_id="pol-" + uuid.uuid4().hex,
            action_taken="logged",
            policy_id=pid,
        ),
        EVT_INTAKE_REJECTED_SIGNATURE: build_policy_event(
            EVT_INTAKE_REJECTED_SIGNATURE,
            scope=system_scope(),
            request_id="pol-" + uuid.uuid4().hex,
            action_taken="blocked",
            violation_type="signature.invalid",
        ),
        EVT_INTAKE_REJECTED_SCOPE_MISMATCH: build_policy_event(
            EVT_INTAKE_REJECTED_SCOPE_MISMATCH,
            scope=_real_scope(),
            request_id="pol-" + uuid.uuid4().hex,
            action_taken="blocked",
            violation_type="scope_mismatch.tenant_id",
        ),
        EVT_INTAKE_REJECTED_REPLAY: build_policy_event(
            EVT_INTAKE_REJECTED_REPLAY,
            scope=_real_scope(),
            request_id="pol-" + uuid.uuid4().hex,
            action_taken="blocked",
            policy_id=pid,
            violation_type="replay",
        ),
        EVT_INTAKE_REJECTED_SCHEMA: build_policy_event(
            EVT_INTAKE_REJECTED_SCHEMA,
            scope=system_scope(),
            request_id="pol-" + uuid.uuid4().hex,
            action_taken="blocked",
            violation_type="schema.invalid",
        ),
        EVT_DECISION_ALLOW: build_policy_event(
            EVT_DECISION_ALLOW,
            scope=_real_scope(),
            request_id="req-" + uuid.uuid4().hex[:16],
            action_taken="logged",
            policy_id=pid,
            requested_model="gpt-4o",
        ),
        EVT_DECISION_DENY: build_policy_event(
            EVT_DECISION_DENY,
            scope=_real_scope(),
            request_id="req-" + uuid.uuid4().hex[:16],
            action_taken="blocked",
            policy_id=pid,
            requested_model="gpt-4",
            violation_type="model_denied",
        ),
    }


@pytest.mark.parametrize("event_type", sorted(POLICY_EVENT_TYPES))
def test_emitted_event_conforms_to_contract(event_type: str):
    """Each emitted event validates against the full schema.

    Validity against the top-level `oneOf` already proves it matched EXACTLY ONE
    branch (oneOf semantics) — i.e. the new variants are mutually exclusive with
    each other and with the existing variants.
    """
    validator = Draft202012Validator(_schema(), format_checker=Draft202012Validator.FORMAT_CHECKER)
    event = _emitted_samples()[event_type]
    errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
    assert not errors, f"{event_type} failed contract: {[e.message for e in errors]}"
