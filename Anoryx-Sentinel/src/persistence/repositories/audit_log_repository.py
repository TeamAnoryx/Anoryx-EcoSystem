"""AuditLogRepository — append-only tamper-evident events_audit_log (F-003b).

APPEND-ONLY: No update or delete methods exist. The DB also enforces this via
BEFORE UPDATE/DELETE triggers and RLS (migration 0005).

HASH CHAIN INTEGRITY:
  row_hash = SHA-256(canonical_json({...all content fields..., prev_hash}))

Concurrent insert safety: chain tip is locked via a transaction-scoped Postgres
advisory lock (pg_advisory_xact_lock).  The lock id is _CHAIN_ADVISORY_LOCK_ID.
This serializes the critical section (tip fetch → insert) globally within the DB.
The lock is released automatically at transaction end.

SESSION REQUIREMENT (F-003b, ADR-0005):
  append(), _get_tip_hash(), and validate_chain() MUST run on the PRIVILEGED
  session (get_privileged_session() / DATABASE_URL / BYPASSRLS role).

  Reason: the chain is a single global ordered sequence across ALL tenants.
  On a tenant-scoped session (sentinel_app + RLS), events_audit_log is filtered
  to rows for the current tenant only. A tip-read on a tenant session would
  return that tenant's last row, not the global tip — so a subsequent append()
  would compute prev_hash against the wrong predecessor and FORK THE CHAIN.
  validate_chain() on a tenant session would walk only one tenant's subset and
  report either a spurious break (gaps in sequence_number) or validate a
  non-global fragment. Both are silent corruption signals.

  _assert_privileged_session() is called at the start of each chain operation.
  PRIMARY CHECK: it queries `SELECT current_user` and rejects the session if
  current_user equals SENTINEL_APP_ROLE ("sentinel_app").  This is the
  LOAD-BEARING guard — a sentinel_app connection cannot change its Postgres
  role identity regardless of any GUC SET statements it issues.
  SECONDARY CHECK (defense-in-depth): it also verifies that app.session_kind
  equals 'privileged', a GUC set at connect time by the privileged engine's
  event hook.  This marker ALONE is insufficient because Postgres allows any
  role to SET a custom GUC; it serves as corroboration, not the primary gate.
  BOTH checks must pass; if either fails the operation is refused.
  Fail-closed: if the method cannot confirm it is privileged, it refuses.

validate_chain() walks all rows in sequence_number order using async streaming
(stream_scalars) to avoid materializing the entire table in memory.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.database import SENTINEL_APP_ROLE, PrivilegedSessionRequiredError
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
        "severity": row.severity,  # contracts/events.schema.json: PiiBlockedEvent.severity
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
        "status": row.status,  # ComplianceCheckedEvent.status (F-002)
        "detected_endpoint": row.detected_endpoint,
        "traffic_volume": row.traffic_volume,
        "first_seen_at": row.first_seen_at,
        # routing_decision variant (F-006, ADR-0008 §5.6) — fixed position,
        # immediately before prev_hash, matching hash_chain.CANONICAL_FIELDS.
        "selected_provider": row.selected_provider,
        "routing_reason": row.routing_reason,
        "outcome": row.outcome,
        "attempt_index": row.attempt_index,
        "requested_model": row.requested_model,
        # F-007 (ADR-0010 §8) variant fields — fixed position before the chain field.
        "judge_score": float(row.judge_score) if row.judge_score is not None else None,
        "judge_confidence": (
            float(row.judge_confidence) if row.judge_confidence is not None else None
        ),
        "final_score": float(row.final_score) if row.final_score is not None else None,
        "judge_model": row.judge_model,
        "judge_preset": row.judge_preset,
        "judge_outcome": row.judge_outcome,
        "audit_mode": row.audit_mode,
        "classifier_reason": row.classifier_reason,
        # F-014 (ADR-0017 §10 D9) — actor_id: passed through so canonical_json()
        # can apply the opt-in-when-present rule (included in hash iff not None).
        "actor_id": row.actor_id,
        # F-018 (ADR-0021 §7) — shadow_ai_candidate_detected variant fields. Passed
        # through so canonical_json() applies the same opt-in-when-present rule
        # (included in hash iff not None; None for every non-candidate row).
        "confidence_band": row.confidence_band,
        "fired_signals": row.fired_signals,
        "candidate_key": row.candidate_key,
        # F-020 (ADR-0023 §5.4) — webhook_provider, failure_class, and config_action are
        # hash-folded via the opt-in-when-present rule in canonical_json(); all three MUST
        # be read back here so validate_chain() recomputes the identical canonical form that
        # append() hashed. delivery_attempts is intentionally NOT returned/folded here because
        # it is a mutable counter (cross-ref hash_chain.canonical_json()).
        "webhook_provider": row.webhook_provider,
        "failure_class": row.failure_class,
        "config_action": row.config_action,
        "prev_hash": row.prev_hash,
    }


class AuditLogRepository:
    """Append-only repository for the tamper-evident events_audit_log.

    The session passed to __init__ is used for all operations.

    PRIVILEGED SESSION REQUIRED for chain ops (F-003b / ADR-0005):
    append(), _get_tip_hash(), and validate_chain() assert they are running on
    the privileged session (DATABASE_URL / BYPASSRLS) before executing. Calling
    any of these methods on a tenant-scoped session raises
    PrivilegedSessionRequiredError immediately — the chain is never read or
    written on a filtered (tenant-scoped) view.

    list_for_tenant() is the only method safe to call on a tenant session; it
    does an explicit WHERE tenant_id = ... and the RLS predicate also filters
    the visible rows to the caller's tenant.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _assert_privileged_session(self) -> None:
        """Assert this session is the privileged (non-tenant-scoped) session.

        PRIMARY CHECK (load-bearing): queries the Postgres current_user.
        If current_user is SENTINEL_APP_ROLE ("sentinel_app") the session is
        the non-privileged app role and MUST be rejected.  A sentinel_app
        connection cannot change its Postgres role identity via any SET
        statement — the role is fixed at login time for the pool lifetime.

        SECONDARY CHECK (defense-in-depth corroboration): reads
        app.session_kind, which the privileged engine sets to 'privileged' via
        a connect-time event hook (database.py).  This marker alone is
        insufficient — Postgres allows any role to SET a custom GUC in its own
        session — but if BOTH the role check and the marker check pass the
        caller has high confidence they are on the correct engine.

        BOTH checks must pass.  Fail-closed: if either check cannot confirm
        privilege, the operation is refused with PrivilegedSessionRequiredError.
        """
        # PRIMARY: role check — the only forgery-resistant assertion.
        role_result = await self._session.execute(text("SELECT current_user"))
        current_role: str | None = role_result.scalar_one_or_none()
        if current_role == SENTINEL_APP_ROLE:
            raise PrivilegedSessionRequiredError(
                f"Chain operation (append / _get_tip_hash / validate_chain) must "
                f"run on the privileged session (get_privileged_session()). "
                f"The current Postgres role is {current_role!r} (the non-privileged "
                f"sentinel_app role). Running chain ops on a tenant session would "
                f"truncate the visible rows to one tenant's subset and fork or "
                f"corrupt the global hash chain. "
                f"HINT: the GUC app.current_tenant_id is irrelevant to this check — "
                f"clearing or unsetting the GUC does NOT grant chain-op access."
            )
        # SECONDARY: session-kind marker — corroboration, not load-bearing.
        marker_result = await self._session.execute(
            text("SELECT current_setting('app.session_kind', true)")
        )
        session_kind: str | None = marker_result.scalar_one_or_none()
        if session_kind != "privileged":
            raise PrivilegedSessionRequiredError(
                "Chain operation requires a session opened via get_privileged_session(). "
                "The app.session_kind marker is not 'privileged' on this connection "
                f"(got {session_kind!r}). This is the secondary defense-in-depth check. "
                "Ensure AuditLogRepository is constructed with a session from "
                "get_privileged_session(), not get_tenant_session()."
            )

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
        Raises PrivilegedSessionRequiredError if called on a tenant session.
        """
        await self._assert_privileged_session()
        self._validate_event_data(event_data)

        # Acquire a transaction-scoped advisory lock.
        # This serializes all concurrent inserts into the chain globally.
        # The lock is released automatically at transaction end.
        await self._session.execute(
            text(f"SELECT pg_advisory_xact_lock({_CHAIN_ADVISORY_LOCK_ID})")
        )

        # Fetch the current chain tip (last row by sequence_number).
        # Use the unchecked form — we already asserted privileged above.
        prev_hash = await self._get_tip_hash_unchecked()

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
            severity=row_data.get("severity"),  # events.schema.json: PiiBlockedEvent.severity
            action_taken=row_data.get("action_taken"),
            classifier_score=row_data.get("classifier_score"),
            rule_matched=row_data.get("rule_matched"),
            secret_type=row_data.get("secret_type"),
            direction=row_data.get("direction"),
            policy_id=row_data.get("policy_id"),
            violation_type=row_data.get("violation_type"),
            framework=row_data.get("framework"),
            control_id=row_data.get("control_id"),
            status=row_data.get("status"),  # ComplianceCheckedEvent.status (F-002)
            detected_endpoint=row_data.get("detected_endpoint"),
            traffic_volume=row_data.get("traffic_volume"),
            first_seen_at=row_data.get("first_seen_at"),
            # routing_decision variant (F-006, ADR-0008 §5.6)
            selected_provider=row_data.get("selected_provider"),
            routing_reason=row_data.get("routing_reason"),
            outcome=row_data.get("outcome"),
            attempt_index=row_data.get("attempt_index"),
            requested_model=row_data.get("requested_model"),
            # F-007 (ADR-0010 §8) variant fields.
            judge_score=row_data.get("judge_score"),
            judge_confidence=row_data.get("judge_confidence"),
            final_score=row_data.get("final_score"),
            judge_model=row_data.get("judge_model"),
            judge_preset=row_data.get("judge_preset"),
            judge_outcome=row_data.get("judge_outcome"),
            audit_mode=row_data.get("audit_mode"),
            classifier_reason=row_data.get("classifier_reason"),
            # F-014 (ADR-0017 §10 D9) — actor_id attribution column.
            # Flows from event_data through row_data into both the hash input
            # (compute_row_hash above) and the stored column. canonical_json()
            # applies the opt-in-when-present rule: None → omitted from hash;
            # non-None UUID → included in hash (tamper-evident).
            actor_id=row_data.get("actor_id"),
            # F-018 (ADR-0021 §7) — shadow_ai_candidate_detected variant columns.
            confidence_band=row_data.get("confidence_band"),
            fired_signals=row_data.get("fired_signals"),
            candidate_key=row_data.get("candidate_key"),
            # F-020 (ADR-0023 §5.2/§5.4) — outbound-webhook signal columns. Without
            # mapping webhook_provider/failure_class/config_action here, those columns
            # would store NULL while compute_row_hash() above folded the non-null values
            # into row_hash, breaking validate_chain() at the first webhook event (the
            # chain stores a hash computed WITH the values but recomputes WITHOUT them).
            # All three are mapped on both append (store) and _row_to_hash_data (verify)
            # so the two paths agree. delivery_attempts is NOT hash-folded (mutable counter).
            webhook_provider=row_data.get("webhook_provider"),
            delivery_attempts=row_data.get("delivery_attempts"),
            failure_class=row_data.get("failure_class"),
            config_action=row_data.get("config_action"),
            # chain fields
            prev_hash=prev_hash,
            row_hash=row_hash,
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def _get_tip_hash_unchecked(self) -> str:
        """Return the row_hash of the last chain row, or GENESIS_HASH.

        Internal helper: does NOT assert the privileged session.  Callers
        that need the session guard must use _get_tip_hash() instead.
        Exists to avoid a redundant round-trip when append() — which already
        called _assert_privileged_session() — needs the tip hash.
        """
        stmt = (
            select(EventsAuditLog.row_hash).order_by(EventsAuditLog.sequence_number.desc()).limit(1)
        )
        result = await self._session.execute(stmt)
        tip_hash = result.scalar_one_or_none()
        return tip_hash if tip_hash is not None else GENESIS_HASH

    async def _get_tip_hash(self) -> str:
        """Return the row_hash of the last row in the chain, or GENESIS_HASH.

        Reads the GLOBAL chain across all tenants. Must be called on the
        privileged session. Raises PrivilegedSessionRequiredError otherwise.
        Public / external callers (e.g. standalone tip inspection) should use
        this form. append() uses _get_tip_hash_unchecked() to avoid a second
        round-trip after the guard already ran.
        """
        await self._assert_privileged_session()
        return await self._get_tip_hash_unchecked()

    async def validate_chain(self) -> ChainValidationResult:
        """Walk all rows in sequence_number order and verify the hash chain.

        Streams rows using stream_scalars() to avoid materialising the entire
        table in memory on large chains.

        For each row, recomputes row_hash from content + prev_hash and checks:
        1. row.prev_hash == previous row's row_hash (or GENESIS_HASH for first row).
        2. row.row_hash == recomputed hash.

        Returns a ChainValidationResult. Does NOT raise on mismatch — reports it.
        Must be called on the privileged session (DATABASE_URL / BYPASSRLS) so it
        walks the GLOBAL chain across all tenants, not a tenant-filtered subset.
        Raises PrivilegedSessionRequiredError if called on a tenant session.
        """
        await self._assert_privileged_session()
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

        # Belt-and-suspenders: after the role assert above, this case can only
        # arise if the chain is genuinely empty.  But we explicitly refuse to
        # return is_valid=True with rows_checked=0 from a non-privileged session
        # (which would be a false-passing validation over an RLS-truncated empty
        # view).  The role assert above already prevents a non-privileged caller
        # from reaching here; this guard is a fail-closed backstop.
        if checked == 0:
            # Re-confirm we are on the privileged role before reporting a clean
            # empty-chain result.  If somehow the assert above was bypassed and
            # we are on the app role, raise rather than return is_valid=True.
            recheck = await self._session.execute(text("SELECT current_user"))
            recheck_role: str | None = recheck.scalar_one_or_none()
            if recheck_role == SENTINEL_APP_ROLE:
                raise PrivilegedSessionRequiredError(
                    "validate_chain() reached zero-rows result on a non-privileged "
                    "session. Refusing to report is_valid=True over an RLS-truncated "
                    "view. Use get_privileged_session() for chain validation."
                )

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

    async def list_for_tenant_after(
        self,
        tenant_id: str,
        *,
        after_sequence: int = 0,
        limit: int = _LIST_DEFAULT_LIMIT,
    ) -> list[EventsAuditLog]:
        """Keyset page of a tenant's events: sequence_number > after_sequence, ASC.

        F-012 audit-read API (ADR-0014 D5): keyset pagination on the monotonic
        append-only PK is stable under concurrent appends (no offset drift). Safe
        on the tenant session — RLS plus an explicit WHERE tenant_id scope it to
        the caller; this is a pure read (no writes — R5/vector 9).
        Default limit 100, hard max 1000, values <= 0 rejected.
        """
        if limit <= 0:
            raise ValueError(f"limit must be > 0, got {limit}")
        effective_limit = min(limit, _LIST_MAX_LIMIT)
        stmt = (
            select(EventsAuditLog)
            .where(EventsAuditLog.tenant_id == tenant_id)
            .where(EventsAuditLog.sequence_number > after_sequence)
            .order_by(EventsAuditLog.sequence_number.asc())
            .limit(effective_limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_for_tenant_by_event_type(
        self,
        tenant_id: str,
        event_type: str,
        *,
        limit: int = _LIST_DEFAULT_LIMIT,
    ) -> list[EventsAuditLog]:
        """Return a tenant's rows of one event_type, newest first (bounded).

        F-018 (ADR-0021 §5/§6): the shadow-AI candidate analysis reads recent
        `shadow_ai_detected_outbound` rows (and `shadow_ai_candidate_detected`
        rows for dedup) on the TARGET tenant session. Pure read — RLS plus an
        explicit WHERE tenant_id scope it to the caller (vector 10). Default
        limit 100, hard max 1000, values <= 0 rejected.
        """
        if limit <= 0:
            raise ValueError(f"limit must be > 0, got {limit}")
        effective_limit = min(limit, _LIST_MAX_LIMIT)
        stmt = (
            select(EventsAuditLog)
            .where(EventsAuditLog.tenant_id == tenant_id)
            .where(EventsAuditLog.event_type == event_type)
            .order_by(EventsAuditLog.sequence_number.desc())
            .limit(effective_limit)
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
            raise AuditLogAppendError(f"Missing required event fields: {sorted(missing)}")

        event_type = event_data["event_type"]
        if event_type not in VALID_EVENT_TYPES:
            raise AuditLogAppendError(
                f"Unknown event_type: {event_type!r}. " f"Valid types: {sorted(VALID_EVENT_TYPES)}"
            )

        # Per-variant action_taken validation (item 10).
        # Events that require action_taken validate against the allowed set.
        if event_type in ACTION_TAKEN_BY_EVENT_TYPE:
            action_taken = event_data.get("action_taken")
            allowed = ACTION_TAKEN_BY_EVENT_TYPE[event_type]
            if action_taken is None:
                raise AuditLogAppendError(f"action_taken is required for event_type={event_type!r}")
            if action_taken not in allowed:
                raise AuditLogAppendError(
                    f"Invalid action_taken={action_taken!r} for event_type={event_type!r}. "
                    f"Allowed: {sorted(allowed)}"
                )
