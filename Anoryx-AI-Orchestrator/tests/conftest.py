"""Shared test fixtures (O-003). Root-level: harmless fixtures only (no DB autouse here).

The DB harness lives in tests/integration/conftest.py so it is scoped to the integration
tests and never runs for the contract/unit lanes.

make_valid_envelope() returns a fresh, contract-valid O-002 envelope wrapping a
policy_decision_deny F-002 payload (the same shape the O-001/O-002 contract tests prove
validates against events.schema.json + event-envelope.schema.json UNMODIFIED). Fresh
UUIDs per call keep tests isolated (no idempotency_key collisions within a run). The three
consumer invariants hold by construction: event_type == payload.event_type,
idempotency_key == payload.event_id, source_product == "sentinel".
"""

from __future__ import annotations

import uuid
from typing import Any, Callable

import pytest


def _build_valid_envelope() -> dict[str, Any]:
    event_id = str(uuid.uuid4())
    request_id = "req-" + uuid.uuid4().hex[:24]
    return {
        "schema_version": 1,
        "envelope_id": str(uuid.uuid4()),
        "event_type": "policy_decision_deny",
        "source_product": "sentinel",
        "occurred_at": "2026-06-26T12:00:01Z",
        "idempotency_key": event_id,  # invariant: == payload.event_id
        "sequence": 1024,
        "correlation_id": request_id,
        "payload": {
            "event_type": "policy_decision_deny",
            "tenant_id": str(uuid.uuid4()),
            "team_id": str(uuid.uuid4()),
            "project_id": str(uuid.uuid4()),
            "agent_id": "gateway-core",
            "event_id": event_id,
            "event_timestamp": "2026-06-26T12:00:00Z",
            "request_id": request_id,
            "action_taken": "blocked",
            "policy_id": str(uuid.uuid4()),
            "requested_model": "gpt-4o",
            "violation_type": "budget_cost_exceeded",
        },
    }


@pytest.fixture
def make_valid_envelope() -> Callable[[], dict[str, Any]]:
    """Return a factory producing a fresh contract-valid envelope on each call."""
    return _build_valid_envelope
