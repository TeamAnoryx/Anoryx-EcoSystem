"""Contract conformance: F-020 webhook audit event dicts validate against
contracts/events.schema.json.

This is the PERMANENT GUARD that would have caught the original bug (violation_type
passthrough vs. the named fields failure_class / config_action).

Mirror of tests/policy/test_event_contract.py (which covers F-008 events) —
same Draft202012Validator pattern, same _schema() helper.

OFFLINE: no DB, no Redis, no network. Pure in-memory schema validation.

Contract claims verified:
  - WebhookDeliveredEvent must have webhook_provider + delivery_attempts; no
    failure_class, no config_action, no violation_type.
  - WebhookDeliveryFailedEvent must have failure_class (named field, NOT violation_type);
    additionalProperties:false means violation_type present → FAILS.
  - WebhookConfigUpdatedEvent must have config_action (named field, NOT violation_type);
    additionalProperties:false means violation_type present → FAILS.

Regression trap:
  test_violation_type_is_not_accepted_on_webhook_delivery_failed and
  test_violation_type_is_not_accepted_on_webhook_config_updated MUST FAIL if anyone
  renames failure_class back to violation_type or adds a violation_type passthrough.
  They do this by asserting that a dict WITH violation_type (and WITHOUT the named field)
  fails schema validation.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

_EVENTS_SCHEMA_PATH = Path(__file__).parents[3] / "contracts" / "events.schema.json"

# ---------------------------------------------------------------------------
# Shared IDs (synthetic UUIDs — no real PII).
# ---------------------------------------------------------------------------

_TENANT_ID = str(uuid.uuid4())
_TEAM_ID = str(uuid.uuid4())
_PROJECT_ID = str(uuid.uuid4())
_WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"


def _schema() -> dict:
    with open(_EVENTS_SCHEMA_PATH, "rb") as fh:
        return json.load(fh)


def _validator() -> Draft202012Validator:
    return Draft202012Validator(
        _schema(),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


# ---------------------------------------------------------------------------
# Helpers to build valid event dicts matching exactly what the emit functions
# produce (mirroring orchestration/webhooks/audit_events.py and admin/audit.py).
# ---------------------------------------------------------------------------


def _make_webhook_delivered_event(
    *,
    tenant_id: str = _TENANT_ID,
    team_id: str = _TEAM_ID,
    project_id: str = _PROJECT_ID,
    webhook_provider: str = "slack",
    delivery_attempts: int = 1,
) -> dict:
    """Construct the exact dict emit_webhook_event() produces for webhook_delivered."""
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": "webhook_delivered",
        "event_timestamp": "2026-06-25T00:00:00Z",
        "request_id": "req-" + uuid.uuid4().hex[:20],
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": "webhook-dispatcher",
        "action_taken": "delivered",
        "webhook_provider": webhook_provider,
        "delivery_attempts": delivery_attempts,
    }


def _make_webhook_delivery_failed_event(
    *,
    tenant_id: str = _TENANT_ID,
    team_id: str = _TEAM_ID,
    project_id: str = _PROJECT_ID,
    webhook_provider: str = "splunk",
    delivery_attempts: int = 3,
    failure_class: str = "dead_lettered",
) -> dict:
    """Construct the exact dict emit_webhook_event() produces for webhook_delivery_failed."""
    return {
        "event_id": str(uuid.uuid4()),
        "event_type": "webhook_delivery_failed",
        "event_timestamp": "2026-06-25T00:00:00Z",
        "request_id": "req-" + uuid.uuid4().hex[:20],
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": "webhook-dispatcher",
        "action_taken": "failed",
        "webhook_provider": webhook_provider,
        "delivery_attempts": delivery_attempts,
        "failure_class": failure_class,
    }


def _make_webhook_config_updated_event(
    *,
    tenant_id: str = _TENANT_ID,
    team_id: str = _WILDCARD_UUID,
    project_id: str = _WILDCARD_UUID,
    webhook_provider: str = "jira",
    config_action: str = "created",
    actor_id: str | None = None,
) -> dict:
    """Construct the exact dict emit_admin_event() produces for webhook_config_updated."""
    event: dict = {
        "event_id": str(uuid.uuid4()),
        "event_type": "webhook_config_updated",
        "event_timestamp": "2026-06-25T00:00:00Z",
        "request_id": "req-" + uuid.uuid4().hex[:20],
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": "admin-console",
        "action_taken": "logged",
        "webhook_provider": webhook_provider,
        "config_action": config_action,
    }
    if actor_id is not None:
        event["actor_id"] = actor_id
    return event


# ===========================================================================
# Basic schema health
# ===========================================================================


def test_events_schema_loads_and_is_valid_draft202012():
    """The schema file is loadable and passes Draft 2020-12 meta-validation."""
    schema = _schema()
    Draft202012Validator.check_schema(schema)


def test_webhook_event_defs_present_in_schema():
    """All three webhook variants are defined in both oneOf and $defs."""
    schema = _schema()
    refs = {entry["$ref"].split("/")[-1] for entry in schema["oneOf"]}
    for name in (
        "WebhookDeliveredEvent",
        "WebhookDeliveryFailedEvent",
        "WebhookConfigUpdatedEvent",
    ):
        assert name in refs, f"{name} missing from oneOf"
        assert name in schema["$defs"], f"{name} missing from $defs"


# ===========================================================================
# Valid events pass — all three webhook variants validate successfully.
# ===========================================================================


@pytest.mark.parametrize(
    "provider",
    ["slack", "jira", "splunk"],
)
def test_webhook_delivered_event_valid(provider: str):
    """webhook_delivered with each provider validates against the full schema."""
    validator = _validator()
    event = _make_webhook_delivered_event(webhook_provider=provider, delivery_attempts=1)
    errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
    assert not errors, (
        f"webhook_delivered[{provider}] failed contract validation: "
        f"{[e.message for e in errors]}"
    )


@pytest.mark.parametrize(
    "failure_class",
    ["url_guard_rejected", "transport_error", "http_error", "dead_lettered"],
)
def test_webhook_delivery_failed_event_valid(failure_class: str):
    """webhook_delivery_failed with each failure_class validates against the full schema."""
    validator = _validator()
    event = _make_webhook_delivery_failed_event(failure_class=failure_class)
    errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
    assert not errors, (
        f"webhook_delivery_failed[{failure_class}] failed contract validation: "
        f"{[e.message for e in errors]}"
    )


@pytest.mark.parametrize(
    "config_action",
    ["created", "updated", "deleted"],
)
def test_webhook_config_updated_event_valid(config_action: str):
    """webhook_config_updated with each config_action validates against the full schema."""
    validator = _validator()
    event = _make_webhook_config_updated_event(config_action=config_action)
    errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
    assert not errors, (
        f"webhook_config_updated[{config_action}] failed contract validation: "
        f"{[e.message for e in errors]}"
    )


def test_webhook_config_updated_with_actor_id_valid():
    """webhook_config_updated with optional actor_id still validates."""
    validator = _validator()
    event = _make_webhook_config_updated_event(
        config_action="updated",
        actor_id=str(uuid.uuid4()),
    )
    errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
    assert not errors, (
        f"webhook_config_updated with actor_id failed validation: " f"{[e.message for e in errors]}"
    )


def test_webhook_config_updated_without_actor_id_valid():
    """webhook_config_updated WITHOUT actor_id (break-glass path) validates."""
    validator = _validator()
    event = _make_webhook_config_updated_event(config_action="deleted", actor_id=None)
    errors = sorted(validator.iter_errors(event), key=lambda e: list(e.path))
    assert not errors, (
        f"webhook_config_updated without actor_id failed validation: "
        f"{[e.message for e in errors]}"
    )


# ===========================================================================
# REGRESSION TRAP — violation_type passthrough MUST be rejected.
#
# These tests FAIL if anyone renames failure_class back to violation_type or
# re-introduces a violation_type passthrough on webhook events.
#
# They work because the schema has additionalProperties:false on each variant,
# so any unknown field causes a validation error.
# ===========================================================================


def test_violation_type_is_not_accepted_on_webhook_delivery_failed():
    """REGRESSION TRAP: violation_type on webhook_delivery_failed MUST fail validation.

    webhook_delivery_failed is additionalProperties:false.  violation_type is NOT a
    defined property.  If this test passes, the schema correctly rejects the old bug.
    If this test were to FAIL (i.e. the validator accepts the dict), that means someone
    re-introduced violation_type on this event — which is the original contract bug.

    This test INTENTIONALLY constructs a STALE/WRONG dict (violation_type instead of
    failure_class) and asserts the schema REJECTS it.
    """
    validator = _validator()
    # Build a dict with violation_type instead of failure_class.
    wrong_event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "webhook_delivery_failed",
        "event_timestamp": "2026-06-25T00:00:00Z",
        "request_id": "req-" + uuid.uuid4().hex[:20],
        "tenant_id": _TENANT_ID,
        "team_id": _TEAM_ID,
        "project_id": _PROJECT_ID,
        "agent_id": "webhook-dispatcher",
        "action_taken": "failed",
        "webhook_provider": "splunk",
        "delivery_attempts": 3,
        # WRONG FIELD: should be failure_class.  Schema must reject this.
        "violation_type": "dead_lettered",
    }
    errors = list(validator.iter_errors(wrong_event))
    assert errors, (
        "REGRESSION TRAP FAILED: The schema accepted violation_type on "
        "webhook_delivery_failed instead of rejecting it. "
        "This means either (a) additionalProperties:false is missing, or "
        "(b) violation_type was re-added to the schema (reverting the bug fix). "
        "The field must be 'failure_class', NOT 'violation_type'."
    )


def test_violation_type_is_not_accepted_on_webhook_config_updated():
    """REGRESSION TRAP: violation_type on webhook_config_updated MUST fail validation.

    Same design as above — config_action is the correct field, not violation_type.
    If this assertion fails, someone reintroduced violation_type on this event.
    """
    validator = _validator()
    wrong_event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "webhook_config_updated",
        "event_timestamp": "2026-06-25T00:00:00Z",
        "request_id": "req-" + uuid.uuid4().hex[:20],
        "tenant_id": _TENANT_ID,
        "team_id": _WILDCARD_UUID,
        "project_id": _WILDCARD_UUID,
        "agent_id": "admin-console",
        "action_taken": "logged",
        "webhook_provider": "jira",
        # WRONG FIELD: should be config_action. Schema must reject this.
        "violation_type": "created",
    }
    errors = list(validator.iter_errors(wrong_event))
    assert errors, (
        "REGRESSION TRAP FAILED: The schema accepted violation_type on "
        "webhook_config_updated instead of rejecting it. "
        "This means either (a) additionalProperties:false is missing, or "
        "(b) violation_type was re-added to the schema (reverting the bug fix). "
        "The field must be 'config_action', NOT 'violation_type'."
    )


def test_failure_class_missing_on_webhook_delivery_failed_is_rejected():
    """webhook_delivery_failed without required failure_class must fail validation.

    failure_class is in the required list — omitting it must be caught.
    """
    validator = _validator()
    missing_event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "webhook_delivery_failed",
        "event_timestamp": "2026-06-25T00:00:00Z",
        "request_id": "req-" + uuid.uuid4().hex[:20],
        "tenant_id": _TENANT_ID,
        "team_id": _TEAM_ID,
        "project_id": _PROJECT_ID,
        "agent_id": "webhook-dispatcher",
        "action_taken": "failed",
        "webhook_provider": "splunk",
        "delivery_attempts": 3,
        # failure_class is intentionally ABSENT.
    }
    errors = list(validator.iter_errors(missing_event))
    assert errors, (
        "Schema accepted webhook_delivery_failed without required 'failure_class'. "
        "It must be in the required list and validated as present."
    )


def test_config_action_missing_on_webhook_config_updated_is_rejected():
    """webhook_config_updated without required config_action must fail validation."""
    validator = _validator()
    missing_event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "webhook_config_updated",
        "event_timestamp": "2026-06-25T00:00:00Z",
        "request_id": "req-" + uuid.uuid4().hex[:20],
        "tenant_id": _TENANT_ID,
        "team_id": _WILDCARD_UUID,
        "project_id": _WILDCARD_UUID,
        "agent_id": "admin-console",
        "action_taken": "logged",
        "webhook_provider": "jira",
        # config_action is intentionally ABSENT.
    }
    errors = list(validator.iter_errors(missing_event))
    assert errors, (
        "Schema accepted webhook_config_updated without required 'config_action'. "
        "It must be in the required list and validated as present."
    )


def test_unknown_failure_class_value_rejected():
    """failure_class enum must only allow the four defined values."""
    validator = _validator()
    bad_event = _make_webhook_delivery_failed_event()
    bad_event["failure_class"] = "unknown_class"  # not in the enum
    errors = list(validator.iter_errors(bad_event))
    assert errors, "Schema accepted an unknown failure_class value; enum validation not working."


def test_unknown_config_action_value_rejected():
    """config_action enum must only allow created/updated/deleted."""
    validator = _validator()
    bad_event = _make_webhook_config_updated_event()
    bad_event["config_action"] = "patched"  # not in the enum
    errors = list(validator.iter_errors(bad_event))
    assert errors, "Schema accepted an unknown config_action value; enum validation not working."


def test_unknown_webhook_provider_value_rejected():
    """webhook_provider enum must only allow slack/jira/splunk."""
    validator = _validator()
    bad_event = _make_webhook_delivered_event()
    bad_event["webhook_provider"] = "teams"  # not in the enum
    errors = list(validator.iter_errors(bad_event))
    assert errors, "Schema accepted an unknown webhook_provider; enum validation not working."


# ===========================================================================
# Verify the emit code path produces schema-conformant dicts.
# Uses the real emit functions (pure Python, no DB) by mocking the repository.
# ===========================================================================


@pytest.mark.asyncio
async def test_emit_webhook_event_produces_conformant_webhook_delivered():
    """Calling emit_webhook_event with event_type='webhook_delivered' produces a
    schema-valid event_data dict (intercepted before DB write).
    """
    from unittest.mock import MagicMock, patch

    captured: list[dict] = []

    async def _capture_append(event_data: dict) -> MagicMock:
        captured.append(dict(event_data))
        return MagicMock()

    from orchestration.webhooks.audit_events import emit_webhook_event

    session_mock = MagicMock()
    mock_repo = MagicMock()
    mock_repo.append = _capture_append

    with patch(
        "orchestration.webhooks.audit_events.AuditLogRepository",
        return_value=mock_repo,
    ):
        await emit_webhook_event(
            session_mock,
            event_type="webhook_delivered",
            tenant_id=_TENANT_ID,
            team_id=_TEAM_ID,
            project_id=_PROJECT_ID,
            request_id="req-" + uuid.uuid4().hex[:20],
            webhook_provider="slack",
            delivery_attempts=1,
        )

    assert len(captured) == 1, "emit_webhook_event must call repository.append once"
    event_data = captured[0]

    validator = _validator()
    errors = sorted(validator.iter_errors(event_data), key=lambda e: list(e.path))
    assert not errors, (
        f"emit_webhook_event produced non-conformant dict for webhook_delivered: "
        f"{[e.message for e in errors]}\nEvent dict: {event_data!r}"
    )

    # Confirm failure_class is NOT present on a webhook_delivered event.
    assert (
        "failure_class" not in event_data
    ), "failure_class must NOT be present on webhook_delivered events"
    # Confirm violation_type is NOT present.
    assert (
        "violation_type" not in event_data
    ), "violation_type must NOT be present on webhook audit events"


@pytest.mark.asyncio
async def test_emit_webhook_event_produces_conformant_webhook_delivery_failed():
    """emit_webhook_event with event_type='webhook_delivery_failed' and failure_class
    produces a schema-valid dict with failure_class (not violation_type).
    """
    from unittest.mock import MagicMock, patch

    captured: list[dict] = []

    async def _capture_append(event_data: dict) -> MagicMock:
        captured.append(dict(event_data))
        return MagicMock()

    from orchestration.webhooks.audit_events import emit_webhook_event

    session_mock = MagicMock()
    mock_repo = MagicMock()
    mock_repo.append = _capture_append

    with patch(
        "orchestration.webhooks.audit_events.AuditLogRepository",
        return_value=mock_repo,
    ):
        await emit_webhook_event(
            session_mock,
            event_type="webhook_delivery_failed",
            tenant_id=_TENANT_ID,
            team_id=_TEAM_ID,
            project_id=_PROJECT_ID,
            request_id="req-" + uuid.uuid4().hex[:20],
            webhook_provider="splunk",
            delivery_attempts=3,
            failure_class="dead_lettered",
        )

    assert len(captured) == 1
    event_data = captured[0]

    validator = _validator()
    errors = sorted(validator.iter_errors(event_data), key=lambda e: list(e.path))
    assert not errors, (
        f"emit_webhook_event produced non-conformant dict for webhook_delivery_failed: "
        f"{[e.message for e in errors]}\nEvent dict: {event_data!r}"
    )

    # Confirm failure_class IS present with the correct value.
    assert (
        event_data.get("failure_class") == "dead_lettered"
    ), f"failure_class must be 'dead_lettered', got {event_data.get('failure_class')!r}"
    # Confirm violation_type is NOT present.
    assert (
        "violation_type" not in event_data
    ), "violation_type must NOT be present on webhook_delivery_failed events"


@pytest.mark.asyncio
async def test_emit_admin_event_produces_conformant_webhook_config_updated():
    """emit_admin_event with event_type='webhook_config_updated' and config_action
    produces a schema-valid dict with config_action (not violation_type).
    """
    from unittest.mock import MagicMock, patch

    captured: list[dict] = []

    async def _capture_append(event_data: dict) -> MagicMock:
        captured.append(dict(event_data))
        return MagicMock()

    from admin.audit import emit_admin_event

    session_mock = MagicMock()
    mock_repo = MagicMock()
    mock_repo.append = _capture_append

    with patch(
        "admin.audit.AuditLogRepository",
        return_value=mock_repo,
    ):
        await emit_admin_event(
            session_mock,
            event_type="webhook_config_updated",
            target_tenant_id=_TENANT_ID,
            request_id="req-" + uuid.uuid4().hex[:20],
            webhook_provider="jira",
            config_action="created",
        )

    assert len(captured) == 1
    event_data = captured[0]

    validator = _validator()
    errors = sorted(validator.iter_errors(event_data), key=lambda e: list(e.path))
    assert not errors, (
        f"emit_admin_event produced non-conformant dict for webhook_config_updated: "
        f"{[e.message for e in errors]}\nEvent dict: {event_data!r}"
    )

    # Confirm config_action IS present.
    assert (
        event_data.get("config_action") == "created"
    ), f"config_action must be 'created', got {event_data.get('config_action')!r}"
    # Confirm violation_type is NOT present.
    assert (
        "violation_type" not in event_data
    ), "violation_type must NOT be present on webhook_config_updated events"


# ===========================================================================
# Cross-variant mutual exclusion (oneOf) sanity checks.
# ===========================================================================


def test_webhook_delivered_does_not_match_delivery_failed_branch():
    """A valid webhook_delivered dict must NOT be accepted as webhook_delivery_failed.

    The full-schema oneOf validator must accept webhook_delivered as exactly one
    variant (the WebhookDeliveredEvent branch), not the WebhookDeliveryFailedEvent
    branch (event_type const mismatch) and not both simultaneously.
    """
    event = _make_webhook_delivered_event()
    # Full-schema oneOf: exactly ONE branch must match — webhook_delivered.
    full_errors = list(_validator().iter_errors(event))
    assert not full_errors, (
        "webhook_delivered event unexpectedly failed full-schema validation — "
        "check oneOf mutual exclusion with delivery_failed branch."
    )
