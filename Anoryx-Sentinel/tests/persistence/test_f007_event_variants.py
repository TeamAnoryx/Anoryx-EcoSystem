"""F-007 event-variant persistence + contract conformance (ADR-0010 §8).

For each of the seven new variants: build a representative event, assert it
validates against contracts/events.schema.json (oneOf), then append it via
AuditLogRepository (privileged session) and assert it persists with the correct
event_type. This proves the 4-site enum wiring + the 8 new columns + the append /
hash-chain mapping are all consistent end to end.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.audit_log_repository import AuditLogRepository

_SCHEMA = json.loads(
    (Path(__file__).parent.parent.parent / "contracts" / "events.schema.json").read_text(
        encoding="utf-8"
    )
)
_VALIDATOR = jsonschema.Draft202012Validator(
    _SCHEMA, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
)


def _envelope(event_type: str) -> dict:
    return {
        "event_type": event_type,
        "tenant_id": str(uuid.uuid4()),
        "team_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "agent_id": "defense",
        "event_id": str(uuid.uuid4()),
        "event_timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "request_id": "req-" + uuid.uuid4().hex[:24],
    }


_VARIANTS = {
    "prompt_injection_detected_ml": {
        "classifier_score": 0.3,
        "judge_score": 0.9,
        "judge_confidence": 0.8,
        "judge_model": "claude-haiku-4-5",
        "final_score": 0.9,
        "audit_mode": "redacted",
        "rule_matched": "INJ-001",
        "action_taken": "blocked",
    },
    "classifier_unconfigured": {"classifier_reason": "no_preset", "action_taken": "logged"},
    "classifier_degraded": {"classifier_reason": "judge_call_failed", "action_taken": "logged"},
    "classifier_invocation_failed": {
        "classifier_reason": "invalid_structured_output",
        "action_taken": "logged",
    },
    "shadow_ai_detected_outbound": {
        "detected_endpoint": "api.openai.com/v1/chat/completions",
        "traffic_volume": 1,
        "first_seen_at": "2026-06-18T12:00:00Z",
        "selected_provider": "openai",
        "action_taken": "logged",
    },
    "recursive_injection_attempt": {
        "classifier_score": 0.55,
        "rule_matched": "INJ-008",
        "action_taken": "blocked",
    },
    "judge_billing_event": {
        "judge_preset": "anthropic:claude-haiku-4-5",
        "judge_model": "claude-haiku-4-5",
        "selected_provider": "anthropic",
        "tokens_in": 12,
        "tokens_out": 4,
        "cost_estimate_cents": 0.05,
        "latency_ms": 120,
        "judge_outcome": "verdict",
        "action_taken": "logged",
    },
}


@pytest.mark.asyncio
@pytest.mark.parametrize("event_type,fields", list(_VARIANTS.items()))
async def test_variant_schema_valid_and_persists(
    session: AsyncSession, event_type: str, fields: dict
) -> None:
    event = {**_envelope(event_type), **fields}

    # (1) Contract conformance — the event matches exactly one oneOf variant.
    errors = list(_VALIDATOR.iter_errors(event))
    assert not errors, f"{event_type} failed schema validation: {errors}"

    # (2) Persistence — append stamps prev_hash/row_hash and writes all columns.
    repo = AuditLogRepository(session)
    row = await repo.append(event)
    assert row.event_type == event_type
    assert row.sequence_number is not None
    assert len(row.row_hash) == 64


@pytest.mark.asyncio
async def test_ml_variant_columns_round_trip(session: AsyncSession) -> None:
    # The new columns persist their values (not silently dropped by append).
    event = {
        **_envelope("prompt_injection_detected_ml"),
        **_VARIANTS["prompt_injection_detected_ml"],
    }
    row = await AuditLogRepository(session).append(event)
    assert float(row.judge_score) == 0.9
    assert float(row.final_score) == 0.9
    assert row.judge_model == "claude-haiku-4-5"
    assert row.audit_mode == "redacted"


@pytest.mark.asyncio
async def test_billing_variant_columns_round_trip(session: AsyncSession) -> None:
    event = {**_envelope("judge_billing_event"), **_VARIANTS["judge_billing_event"]}
    row = await AuditLogRepository(session).append(event)
    assert row.judge_preset == "anthropic:claude-haiku-4-5"
    assert row.judge_outcome == "verdict"
    assert row.selected_provider == "anthropic"
    assert row.tokens_in == 12 and row.tokens_out == 4
