"""AuditLogRepository — append-only tamper-evident events_audit_log (F-003).

APPEND-ONLY: No update or delete methods exist. The DB also enforces this via
BEFORE UPDATE/DELETE triggers and RLS (migration 0005).

HASH CHAIN INTEGRITY:
  row_hash = SHA-256(canonical_json({...all content fields..., prev_hash}))

Concurrent insert safety: chain tip is locked via a transaction-scoped Postgres
advisory lock (pg_advisory_xact_lock).  The lock id is _CHAIN_ADVISORY_LOCK_ID.
This serializes the critical section (tip fetch → insert) globally within the DB.
The lock is released automatically at transaction end.

SESSION NOTE:
  _get_tip_hash() and validate_chain() read ALL rows across all tenants to
  maintain the single global chain.  The session passed in must be able to see
  all rows in events_audit_log (e.g., a session connecting as a BYPASSRLS role,
  or a session where the RLS `OR ... IS NULL` branch applies).  F-003 does not
  enforce which session type is used here — that enforcement is deferred to F-003b.

validate_chain() walks all rows in sequence_number order using async streaming
(stream_scalars) to avoid materializing the entire table in memory.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.hash_chain import GENESIS_HASH, compute_row_hash
from persistence.models.events_audit_log import (
    ACTION_TAKEN_BY_EVENT_TYPE,
    VALID_EVENT_TYPES,
    EventsAuditLog,
)

# Named constant for the advisory lock id used to serialize chain-tip writes.
# Any 64-bit integer is valid; this value is unique to the audit chain.
_CHAIN_ADVISORY_LOCK_ID = 5347209814718263

# Default and maximum page sizes for list_for_tenant.
_LIST_DEFAULT_LIMIT = 100
_LIST_MAX_LIMIT = 1000


class AuditLogAppendError(Exception):
    """Raised when an audit log insert fails validation."""


@dataclass(frozen=True)
class ChainValidationResult:
    """Result of a validate_chain() walk."""

    is_valid: bool
    rows_checked: int
    first_mismatch_sequence: int | None
    error_detail: str | None


def _row_to_hash_data(row: EventsAuditLog) -> dict[str, Any]:
    """Extract the canonical hash fields from an ORM row.

    Column names match contracts/events.schema.json:
      severity — PiiBlockedEvent.severity
      status   — ComplianceCheckedEvent.status
    """
    return {
        "event_id": row.event_id,
        "event_type": row.event_type,
        "event_timestamp": row.event_timestamp,
        "request_id": row.request_id,
        "tenant_id": row.tenant_id,
        "team_id": row.team_id,
        "project_id": row.project_id,
        "agent_id": row.agent_id,
        "model": row.model,
        "tokens_in": row.tokens_in,
        "tokens_out": row.tokens_out,
        "latency_ms": row.latency_ms,
        "cost_estimate_cents": (
            float(row.cost_estimate_cents) if row.cost_estimate_cents is not None else None
        ),
        "pattern_name": row.pattern_name,
        "severity": row.severity,       # contracts/events.schema.json: PiiBlockedEvent.severity
        "action_taken": row.action_taken,
        "classifier_score": (
            float(row.classifier_score) if row.classifier_score is not None else None
        ),
        "rule_matched": row.rule_matched,
        "secret_type": row.secret_type,
        "direction": row.direction,
        "policy_id": row.policy_id,
        "violation_type": row.violation_type,
        "framework": row.framework,
        "control_id": row.control_id,
        "status": row.status,           # contracts/events.schema.json: ComplianceCheckedEvent.status
        "detected_endpoint": row.detected_endpoint,
        "traffic_volume": row.traffic_volume,
        "first_seen_at": row.first_seen_at,
        "prev_hash": row.prev_hash,
    }


class AuditLogRepository:
    """Append-only repository for the tamper-evident events_audit_log.

    The session passed to __init__ is used for all operations.  Chain-tip
    reads in _get_tip_hash() and the full-table walk in validate_chain()
    require a session that can see all rows in events_audit_log across all
    tenants.  Callers are responsible for supplying an appropriate session;
    enforcement of which session type to use is deferred to F-003b.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(self, event_data: dict[str, Any]) -> EventsAuditLog:
        """Append a new event to the audit log.

        Acquires a transaction-scoped advisory lock (_CHAIN_ADVISORY_LOCK_ID)
        to serialize concurrent inserts and prevent hash-chain corruption.
        Computes prev_hash from the current chain tip, then computes row_hash.

        event_data must include all required common fields:
            event_id, event_type, event_timestamp, request_id,
            tenant_id, team_id, project_id, agent_id
        Plus variant-specific fields as applicable.

        Raises AuditLogAppendError for invalid event_type, missing required
        fields, or invalid action_taken for the given event_type.
        """
        self._validate_event_data(event_data)

        # Acquire a transaction-scoped advisory lock.
        # This serializes all concurrent inserts into the chain globally.
        # The lock is released automatically at transaction end.
        await self._session.execute(
            text(f"SELECT pg_advisory_xact_lock({_CHAIN_ADVISORY_LOCK_ID})")
        )

        # Fetch the current chain tip (last row by sequence_number).
        prev_hash = await self._get_tip_hash()

        # Build the row data dict for hashing.
        row_data = dict(event_data)
        row_data["prev_hash"] = prev_hash

        row_hash = compute_row_hash(row_data)

        row = EventsAuditLog(
            event_id=row_data["event_id"],
            event_type=row_data["event_type"],
            event_timestamp=row_data["event_timestamp"],
            request_id=row_data["request_id"],
            tenant_id=row_data["tenant_id"],
            team_id=row_data["team_id"],
            project_id=row_data["project_id"],
            agent_id=row_data["agent_id"],
            # variant fields — column names match events.schema.json
            model=row_data.get("model"),
            tokens_in=row_data.get("tokens_in"),
            tokens_out=row_data.get("tokens_out"),
            latency_ms=row_data.get("latency_ms"),
            cost_estimate_cents=row_data.get("cost_estimate_cents"),
            pattern_name=row_data.get("pattern_name"),
            severity=row_data.get("severity"),      # events.schema.json: PiiBlockedEvent.severity
            action_taken=row_data.get("action_taken"),
            classifier_score=row_data.get("classifier_score"),
            rule_matched=row_data.get("rule_matched"),
            secret_type=row_data.get("secret_type"),
            direction=row_data.get("direction"),
            policy_id=row_data.get("policy_id"),
            violation_type=row_data.get("violation_type"),
            framework=row_data.get("framework"),
            control_id=row_data.get("control_id"),
            status=row_data.get("status"),          # events.schema.json: ComplianceCheckedEvent.status
            detected_endpoint=row_data.get("detected_endpoint"),
            traffic_volume=row_data.get("traffic_volume"),
            first_seen_at=row_data.get("first_seen_at"),
            # chain fields
            prev_hash=prev_hash,
            row_hash=row_hash,
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def _get_tip_hash(self) -> str:
        """Return the row_hash of the last row in the chain, or GENESIS_HASH.

        This query reads the GLOBAL chain (all tenants).  The session must be
        able to see all rows in events_audit_log to maintain the single chain.
        """
        stmt = (
            select(EventsAuditLog.row_hash)
            .order_by(EventsAuditLog.sequence_number.desc())
            .limit(1)
        )
        result = await self._session.execute(stmt)
        tip_hash = result.scalar_one_or_none()
        return tip_hash if tip_hash is not None else GENESIS_HASH

    async def validate_chain(self) -> ChainValidationResult:
        """Walk all rows in sequence_number order and verify the hash chain.

        Streams rows using stream_scalars() to avoid materialising the entire
        table in memory on large chains.

        For each row, recomputes row_hash from content + prev_hash and checks:
        1. row.prev_hash == previous row's row_hash (or GENESIS_HASH for first row).
        2. row.row_hash == recomputed hash.

        Returns a ChainValidationResult. Does NOT raise on mismatch — reports it.
        This is a read-only operation.  The session must be able to see all rows
        in events_audit_log to walk the GLOBAL single chain across all tenants.
        """
        stmt = select(EventsAuditLog).order_by(EventsAuditLog.sequence_number)
        stream = await self._session.stream_scalars(stmt)

        expected_prev_hash = GENESIS_HASH
        checked = 0

        async for row in stream:
            checked += 1
            # Check 1: prev_hash must equal the expected value from the prior row.
            if row.prev_hash != expected_prev_hash:
                return ChainValidationResult(
                    is_valid=False,
                    rows_checked=checked,
                    first_mismatch_sequence=row.sequence_number,
                    error_detail=(
                        f"prev_hash mismatch at sequence={row.sequence_number}: "
                        f"stored={row.prev_hash!r}, expected={expected_prev_hash!r}"
                    ),
                )

            # Check 2: row_hash must equal recomputed hash.
            row_data = _row_to_hash_data(row)
            recomputed = compute_row_hash(row_data)
            if row.row_hash != recomputed:
                return ChainValidationResult(
                    is_valid=False,
                    rows_checked=checked,
                    first_mismatch_sequence=row.sequence_number,
                    error_detail=(
                        f"row_hash mismatch at sequence={row.sequence_number}: "
                        f"stored={row.row_hash!r}, recomputed={recomputed!r}"
                    ),
                )

            expected_prev_hash = row.row_hash

        return ChainValidationResult(
            is_valid=True,
            rows_checked=checked,
            first_mismatch_sequence=None,
            error_detail=None,
        )

    async def list_for_tenant(
        self,
        tenant_id: str,
        limit: int = _LIST_DEFAULT_LIMIT,
        offset: int = 0,
    ) -> list[EventsAuditLog]:
        """Return audit log rows for a tenant (newest first, paginated).

        Default limit: 100.  Hard max: 1000.  Values <= 0 are rejected.
        """
        if limit <= 0:
            raise ValueError(f"limit must be > 0, got {limit}")
        effective_limit = min(limit, _LIST_MAX_LIMIT)
        stmt = (
            select(EventsAuditLog)
            .where(EventsAuditLog.tenant_id == tenant_id)
            .order_by(EventsAuditLog.sequence_number.desc())
            .limit(effective_limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    def _validate_event_data(event_data: dict[str, Any]) -> None:
        """Validate required common fields and per-variant action_taken."""
        required = {
            "event_id",
            "event_type",
            "event_timestamp",
            "request_id",
            "tenant_id",
            "team_id",
            "project_id",
            "agent_id",
        }
        missing = required - event_data.keys()
        if missing:
            raise AuditLogAppendError(
                f"Missing required event fields: {sorted(missing)}"
            )

        event_type = event_data["event_type"]
        if event_type not in VALID_EVENT_TYPES:
            raise AuditLogAppendError(
                f"Unknown event_type: {event_type!r}. "
                f"Valid types: {sorted(VALID_EVENT_TYPES)}"
            )

        # Per-variant action_taken validation (item 10).
        # Events that require action_taken validate against the allowed set.
        if event_type in ACTION_TAKEN_BY_EVENT_TYPE:
            action_taken = event_data.get("action_taken")
            allowed = ACTION_TAKEN_BY_EVENT_TYPE[event_type]
            if action_taken is None:
                raise AuditLogAppendError(
                    f"action_taken is required for event_type={event_type!r}"
                )
            if action_taken not in allowed:
                raise AuditLogAppendError(
                    f"Invalid action_taken={action_taken!r} for event_type={event_type!r}. "
                    f"Allowed: {sorted(allowed)}"
                )
