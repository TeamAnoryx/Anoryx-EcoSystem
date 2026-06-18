"""F-009 rate-limit observability event-variant persistence (ADR-0011 §7/§8).

Mirrors tests/persistence/test_f007_event_variants.py.

For each of the three new variants (rate_limit_degraded, rate_limit_recovered,
rate_limit_redis_error):
  - Append via AuditLogRepository on a privileged session.
  - Assert the row persists with the correct event_type.
  - Assert hash-chain columns are populated (sequence_number, row_hash len=64).

Additional coverage:
  - Vector 16 (ADR-0011 §9): rate_limit_recovered uses WILDCARD_UUID for all
    four stable IDs and agent_id='rate-limiter', as required by the system-ID
    convention (ADR-0011 §7 / D6).
  - Unknown forensic key (redis_error_class) in the event_data dict: append()
    must SUCCEED and persist the row — redis_error_class is NOT a column; it lives
    only in the Redis-Streams event JSON per ADR-0011 §7. The repository maps fields
    via explicit row_data.get() calls so unmapped keys are naturally ignored.
  - Disallowed action_taken ('blocked') for any of the three variants must be
    rejected by ACTION_TAKEN_BY_EVENT_TYPE validation (AuditLogAppendError).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.events_audit_log import ACTION_TAKEN_BY_EVENT_TYPE, VALID_EVENT_TYPES
from persistence.repositories.audit_log_repository import AuditLogAppendError, AuditLogRepository

# Reserved system-ID per ADR-0009 §4 / ADR-0011 §7 (third documented purpose).
WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"


def _now_z() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _envelope(event_type: str, *, system: bool = False) -> dict:
    """Build a minimal valid event envelope.

    When system=True the four stable IDs use WILDCARD_UUID and
    agent_id='rate-limiter', matching the ADR-0011 §7 system-emitted convention.
    """
    if system:
        return {
            "event_type": event_type,
            "tenant_id": WILDCARD_UUID,
            "team_id": WILDCARD_UUID,
            "project_id": WILDCARD_UUID,
            "agent_id": "rate-limiter",
            "event_id": str(uuid.uuid4()),
            "event_timestamp": _now_z(),
            "request_id": "req-" + uuid.uuid4().hex[:24],
            "action_taken": "logged",
        }
    return {
        "event_type": event_type,
        "tenant_id": str(uuid.uuid4()),
        "team_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "agent_id": "rate-limiter",
        "event_id": str(uuid.uuid4()),
        "event_timestamp": _now_z(),
        "request_id": "req-" + uuid.uuid4().hex[:24],
        "action_taken": "logged",
    }


# ---------------------------------------------------------------------------
# 4-site registration checks (pure-Python, no DB required)
# ---------------------------------------------------------------------------


def test_rate_limit_variants_in_valid_event_types() -> None:
    """All three F-009 variants are registered in VALID_EVENT_TYPES."""
    for variant in ("rate_limit_degraded", "rate_limit_recovered", "rate_limit_redis_error"):
        assert variant in VALID_EVENT_TYPES, f"{variant!r} missing from VALID_EVENT_TYPES"


def test_rate_limit_variants_in_action_taken_map() -> None:
    """All three F-009 variants have ACTION_TAKEN_BY_EVENT_TYPE entries."""
    for variant in ("rate_limit_degraded", "rate_limit_recovered", "rate_limit_redis_error"):
        assert (
            variant in ACTION_TAKEN_BY_EVENT_TYPE
        ), f"{variant!r} missing from ACTION_TAKEN_BY_EVENT_TYPE"
        assert ACTION_TAKEN_BY_EVENT_TYPE[variant] == frozenset(
            {"logged"}
        ), f"{variant!r} must only allow action_taken='logged'"


# ---------------------------------------------------------------------------
# Persistence tests (require live DB via privileged session fixture)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "event_type",
    [
        "rate_limit_degraded",
        "rate_limit_recovered",
        "rate_limit_redis_error",
    ],
)
async def test_variant_inserts_successfully(session: AsyncSession, event_type: str) -> None:
    """Each of the three new variants can be appended and persists correctly."""
    event = _envelope(event_type)
    repo = AuditLogRepository(session)
    row = await repo.append(event)

    assert row.event_type == event_type
    assert row.sequence_number is not None
    assert len(row.row_hash) == 64
    assert len(row.prev_hash) == 64
    assert row.action_taken == "logged"


@pytest.mark.asyncio
async def test_vector_16_recovery_event_uses_wildcard_uuid(session: AsyncSession) -> None:
    """Vector 16 (ADR-0011 §9): rate_limit_recovered uses WILDCARD_UUID + agent_id='rate-limiter'.

    The system-ID convention (ADR-0011 §7 D6) requires that recovery events emitted
    by the background health loop carry WILDCARD_UUID for tenant_id/team_id/project_id
    and the reserved slug 'rate-limiter' for agent_id. This test appends such an event
    and asserts the row persists with the correct system IDs, a valid hash chain, and
    event_type='rate_limit_recovered'.
    """
    event = _envelope("rate_limit_recovered", system=True)
    assert event["tenant_id"] == WILDCARD_UUID
    assert event["team_id"] == WILDCARD_UUID
    assert event["project_id"] == WILDCARD_UUID
    assert event["agent_id"] == "rate-limiter"

    repo = AuditLogRepository(session)
    row = await repo.append(event)

    assert row.event_type == "rate_limit_recovered"
    assert row.tenant_id == WILDCARD_UUID
    assert row.team_id == WILDCARD_UUID
    assert row.project_id == WILDCARD_UUID
    assert row.agent_id == "rate-limiter"
    assert row.sequence_number is not None
    assert len(row.row_hash) == 64


@pytest.mark.asyncio
async def test_redis_error_class_key_is_ignored_not_errored(session: AsyncSession) -> None:
    """redis_error_class in event_data is NOT a column — append must SUCCEED.

    ADR-0011 §7 specifies that redis_error_class lives only in the Redis-Streams
    event JSON and the OTel span event, never in an events_audit_log column.
    The repository's explicit row_data.get() field mapping means unknown keys are
    naturally discarded — no stripping happens in the model.

    This test proves that passing redis_error_class through append() does not raise
    and that the row persists correctly (the forensic key is silently dropped from
    the DB row, which is the correct behaviour per ADR-0011 §7/§10).
    """
    event = {
        **_envelope("rate_limit_degraded"),
        "redis_error_class": "RedisConnectionError",  # forensic key — NOT a column
    }
    repo = AuditLogRepository(session)
    # Must NOT raise — unknown keys must be ignored, not cause an error.
    row = await repo.append(event)

    assert row.event_type == "rate_limit_degraded"
    assert row.sequence_number is not None
    assert len(row.row_hash) == 64
    # Confirm the unknown key did not land on the row object.
    assert not hasattr(row, "redis_error_class")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "event_type",
    [
        "rate_limit_degraded",
        "rate_limit_recovered",
        "rate_limit_redis_error",
    ],
)
async def test_disallowed_action_taken_rejected(session: AsyncSession, event_type: str) -> None:
    """action_taken='blocked' must be rejected for all three F-009 variants.

    The ACTION_TAKEN_BY_EVENT_TYPE map restricts these variants to 'logged' only.
    Passing 'blocked' must raise AuditLogAppendError immediately (before any DB I/O).
    """
    event = {**_envelope(event_type), "action_taken": "blocked"}
    repo = AuditLogRepository(session)
    with pytest.raises(AuditLogAppendError, match="Invalid action_taken"):
        await repo.append(event)


@pytest.mark.asyncio
async def test_hash_chain_across_all_three_variants(session: AsyncSession) -> None:
    """Appending all three variants in sequence produces a valid hash chain.

    Inserts rate_limit_degraded -> rate_limit_recovered -> rate_limit_redis_error and
    confirms each row's prev_hash equals the prior row's row_hash (the chain is intact).
    """
    repo = AuditLogRepository(session)
    rows = []
    for event_type in ("rate_limit_degraded", "rate_limit_recovered", "rate_limit_redis_error"):
        row = await repo.append(_envelope(event_type))
        rows.append(row)

    # Each subsequent row's prev_hash must equal the prior row's row_hash.
    for i in range(1, len(rows)):
        assert rows[i].prev_hash == rows[i - 1].row_hash, (
            f"Chain broken between seq {rows[i-1].sequence_number} "
            f"and {rows[i].sequence_number}"
        )
