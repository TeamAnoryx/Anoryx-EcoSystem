"""Webhook-dispatcher audit emission (F-020, ADR-0023 §5.4).

Every terminal delivery outcome is appended to the append-only, hash-chained
audit log via the existing privileged writer, following the F-015 bulk pattern
(src/bulk/audit_events.py) EXACTLY.

Attribution (honest):
  agent_id         = "webhook-dispatcher"  (reserved slug — contracts/ids.md)
  tenant_id        = the SOURCE event's real tenant (honest, NEVER WILDCARD_UUID)
  team_id          = the SOURCE event's real team_id
  project_id       = the SOURCE event's real project_id
  request_id       = the SOURCE event's event_id (per-delivery correlation)
  webhook_provider = bounded provider label — NEVER a URL, NEVER a credential
  action_taken     = "delivered" | "failed"
  delivery_attempts= bounded integer (1..100)

get_privileged_session() does NOT autobegin — wrap in async with session.begin()
as shown in context.py:164-166 and bulk/worker.py:75-78.

NEVER log: target URLs, credentials, raw response bodies, or stack traces.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.audit_log_repository import AuditLogRepository

# Reserved agent_id slug for the webhook-dispatcher principal (contracts/ids.md).
WEBHOOK_DISPATCHER_PRINCIPAL = "webhook-dispatcher"

# Valid event types emitted by this module (must match VALID_EVENT_TYPES in
# persistence/models/events_audit_log.py and migration 0030).
WEBHOOK_EVENT_ACTION: dict[str, str] = {
    "webhook_delivered": "delivered",
    "webhook_delivery_failed": "failed",
}


def _now_rfc3339_z() -> str:
    """RFC3339 UTC with the 'Z' form (matches every production audit writer)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def emit_webhook_event(
    session: AsyncSession,
    *,
    event_type: str,
    tenant_id: str,
    team_id: str,
    project_id: str,
    request_id: str,
    webhook_provider: str,
    delivery_attempts: int,
    failure_class: str | None = None,
) -> None:
    """Append a webhook-dispatcher-attributed audit event on the caller's privileged session.

    Parameters
    ----------
    session:
        A PRIVILEGED session (get_privileged_session()); AuditLogRepository.append()
        asserts it. Caller wraps in async with session.begin():
    event_type:
        One of WEBHOOK_EVENT_ACTION ('webhook_delivered' | 'webhook_delivery_failed').
    tenant_id / team_id / project_id:
        The SOURCE event's real IDs. NEVER WILDCARD_UUID (honest attribution).
    request_id:
        Correlation ID — the source event's event_id.
    webhook_provider:
        Bounded provider label ('slack' | 'jira' | 'splunk'). NEVER a URL.
    delivery_attempts:
        Number of attempts made before this terminal outcome (1..100).
    failure_class:
        Required for 'webhook_delivery_failed'; omit for 'webhook_delivered'.
        Must match the failure_class enum in events.schema.json:
        url_guard_rejected | transport_error | http_error | dead_lettered.

    Raises ValueError for an unknown event_type (defense-in-depth).
    """
    if event_type not in WEBHOOK_EVENT_ACTION:
        raise ValueError(f"not a webhook event_type: {event_type!r}")

    event_data: dict[str, object] = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "event_timestamp": _now_rfc3339_z(),
        "request_id": request_id,
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": WEBHOOK_DISPATCHER_PRINCIPAL,
        "action_taken": WEBHOOK_EVENT_ACTION[event_type],
        "webhook_provider": webhook_provider,
        "delivery_attempts": delivery_attempts,
    }

    # failure_class is required on webhook_delivery_failed (schema validation).
    # The persistence layer has a real failure_class column (migration 0029/0030)
    # that is hash-folded by the repository.  Emit the field exactly as named in
    # contracts/events.schema.json (additionalProperties:false — the name must match).
    if failure_class is not None:
        event_data["failure_class"] = failure_class

    await AuditLogRepository(session).append(event_data)
