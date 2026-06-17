"""routing_decision event persistence + hash-chain tests (F-006, ADR-0008 §5.6).

Proves the new variant is actually persistable and tamper-evident, not merely
schema-valid: append a routing_decision row, then validate_chain() on the
privileged session, and confirm the 5 new columns are covered by the hash
(mutating one breaks validation).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.audit_log_repository import (
    AuditLogAppendError,
    AuditLogRepository,
)


def _uid() -> str:
    return str(uuid.uuid4())


def _routing_event(**overrides) -> dict:
    ev = {
        "event_id": _uid(),
        "event_type": "routing_decision",
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": "req-" + _uid()[:8],
        "tenant_id": _uid(),
        "team_id": _uid(),
        "project_id": _uid(),
        "agent_id": "gateway-core",
        "selected_provider": "anthropic",
        "routing_reason": "fallback-transient",
        "outcome": "fallback_attempted",
        "action_taken": "failed_over",
        "attempt_index": 1,
        "requested_model": "claude-3-haiku",
    }
    ev.update(overrides)
    return ev


@pytest.mark.asyncio
async def test_routing_decision_appends_and_chain_valid(session: AsyncSession) -> None:
    repo = AuditLogRepository(session)
    row = await repo.append(_routing_event(outcome="selected", action_taken="routed"))
    assert row.event_type == "routing_decision"
    assert row.selected_provider == "anthropic"
    assert row.outcome == "selected"
    assert row.attempt_index == 1
    assert row.requested_model == "claude-3-haiku"

    result = await repo.validate_chain()
    assert result.is_valid is True, result.error_detail


def test_routing_columns_covered_by_hash() -> None:
    """The 5 routing_decision columns are part of the canonical hash content.

    Unit-level (no UPDATE — the table trigger blocks UPDATE). Changing any one
    routing field must change the computed row_hash, proving tamper-evidence
    coverage of the new columns (ADR-0008 §5.6).
    """
    from persistence.hash_chain import GENESIS_HASH, compute_row_hash

    base = {
        "event_id": "e1",
        "event_type": "routing_decision",
        "event_timestamp": "2026-06-17T00:00:00Z",
        "request_id": "r1",
        "tenant_id": "t1",
        "team_id": "team1",
        "project_id": "p1",
        "agent_id": "gateway-core",
        "selected_provider": "anthropic",
        "routing_reason": "fallback-transient",
        "outcome": "fallback_attempted",
        "action_taken": "failed_over",
        "attempt_index": 1,
        "requested_model": "claude-3-haiku",
        "prev_hash": GENESIS_HASH,
    }
    base_hash = compute_row_hash(base)
    for field, mutated in [
        ("selected_provider", "openai"),
        ("routing_reason", "cost-routing"),
        ("outcome", "selected"),
        ("attempt_index", 2),
        ("requested_model", "gpt-4o"),
    ]:
        variant = dict(base)
        variant[field] = mutated
        assert compute_row_hash(variant) != base_hash, f"{field} not covered by hash"


@pytest.mark.asyncio
async def test_routing_decision_action_taken_validated(session: AsyncSession) -> None:
    """action_taken must be in {routed, blocked, failed_over} for routing_decision."""
    repo = AuditLogRepository(session)
    with pytest.raises(AuditLogAppendError):
        await repo.append(_routing_event(action_taken="masked"))  # invalid for this variant
