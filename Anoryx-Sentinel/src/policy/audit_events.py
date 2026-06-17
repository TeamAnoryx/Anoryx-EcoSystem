"""Hash-chained audit emission for the seven F-008 policy event variants (ADR-0009 §7).

Every event conforms to contracts/events.schema.json and persists via
AuditLogRepository on the privileged session. Two entry points:

  append_policy_event(session, event)   — append within the CALLER's transaction.
      Used by intake so the accepted-policy persist and its audit row commit (or
      roll back) ATOMICALLY in one transaction (closes the F-004 audit-bypass class).

  emit_policy_event(event)               — open a privileged session, append,
      best-effort (log ERROR + swallow on failure). Used by request-time
      enforcement (policy_decision_*), mirroring the F-006 emit_routing_decision
      precedent: the terminal block is enforced independently and the request's
      terminal usage record is the fail-safe audit gate.

ATTRIBUTION (Decision B): the audit-row tenant_id is the SIGNATURE-RESOLVED tenant
when one exists; for schema-invalid / signature-failed records (no resolvable
tenant) it is the system tenant (constants.SYSTEM_TENANT_ID). Raw disputed body
IDs are NEVER written to the chain — they go only to structured logs keyed by
request_id (handled by the caller).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.database import get_privileged_session
from persistence.repositories.audit_log_repository import AuditLogRepository
from policy.constants import (
    EVT_DECISION_ALLOW,
    EVT_DECISION_DENY,
    GATEWAY_AGENT,
    SYSTEM_TENANT_ID,
)

log = structlog.get_logger(__name__)

_ACTION_LOGGED = "logged"
_ACTION_BLOCKED = "blocked"


def new_intake_request_id() -> str:
    """Synthesize an intake correlation id matching the events.schema request_id pattern.

    Intake is not an HTTP request, but every event requires a request_id of the
    form ^[A-Za-z0-9._-]{1,64}$. "pol-" + uuid hex satisfies it and correlates the
    decision's audit row with its structured-log line.
    """
    return "pol-" + uuid.uuid4().hex


def system_scope() -> dict[str, str]:
    """The system-tenant attribution scope (schema/signature-fail rejections)."""
    return {
        "tenant_id": SYSTEM_TENANT_ID,
        "team_id": SYSTEM_TENANT_ID,
        "project_id": SYSTEM_TENANT_ID,
        "agent_id": GATEWAY_AGENT,
    }


def build_policy_event(
    event_type: str,
    *,
    scope: dict[str, str],
    request_id: str,
    action_taken: str,
    policy_id: str | None = None,
    violation_type: str | None = None,
    requested_model: str | None = None,
) -> dict[str, Any]:
    """Build a contract-conformant event dict reusing only existing audit columns."""
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    event: dict[str, Any] = {
        "event_type": event_type,
        "tenant_id": scope["tenant_id"],
        "team_id": scope["team_id"],
        "project_id": scope["project_id"],
        "agent_id": scope["agent_id"],
        "event_id": str(uuid.uuid4()),
        "event_timestamp": now,
        "request_id": request_id,
        "action_taken": action_taken,
    }
    if policy_id is not None:
        event["policy_id"] = policy_id
    if violation_type is not None:
        event["violation_type"] = violation_type
    if requested_model is not None:
        event["requested_model"] = requested_model
    return event


async def append_policy_event(session: AsyncSession, event: dict[str, Any]) -> None:
    """Append *event* within the caller's (privileged) transaction. Raises on failure."""
    await AuditLogRepository(session).append(event)


async def emit_policy_event(event: dict[str, Any]) -> None:
    """Best-effort append on a fresh privileged session (enforcement observability)."""
    try:
        async with get_privileged_session() as session:
            async with session.begin():
                await AuditLogRepository(session).append(event)
        log.info(
            "policy_event_appended",
            event_type=event.get("event_type"),
            request_id=event.get("request_id"),
        )
    except Exception:
        # Never convert the request outcome on an audit-emit failure (the terminal
        # block is already enforced; the usage record is the fail-safe gate).
        log.error(
            "policy_event_append_failed",
            event_type=event.get("event_type"),
            request_id=event.get("request_id"),
        )


async def emit_policy_decision(
    tenant_context,
    *,
    request_id: str,
    allow: bool,
    policy_id: str | None,
    requested_model: str,
    reason: str | None = None,
) -> None:
    """Best-effort emit of a policy_decision_allow / policy_decision_deny event.

    Mirrors the F-006 emit_routing_decision best-effort posture (ADR-0009 §7): the
    terminal block is enforced independently and the request's terminal usage record
    is the fail-safe audit gate, so a failed decision-emit never converts the outcome.
    """
    scope = {
        "tenant_id": tenant_context.tenant_id,
        "team_id": tenant_context.team_id,
        "project_id": tenant_context.project_id,
        # agent_id is the EMITTING component (gateway-core), not the requesting agent —
        # matches the events.schema description + the F-006 routing_decision convention.
        "agent_id": GATEWAY_AGENT,
    }
    event = build_policy_event(
        EVT_DECISION_ALLOW if allow else EVT_DECISION_DENY,
        scope=scope,
        request_id=request_id,
        action_taken=_ACTION_LOGGED if allow else _ACTION_BLOCKED,
        policy_id=policy_id,
        requested_model=requested_model,
        violation_type=None if allow else reason,
    )
    await emit_policy_event(event)
