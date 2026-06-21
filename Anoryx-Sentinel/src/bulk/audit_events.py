"""Bulk-pipeline audit emission (F-015, ADR-0018 §8 D7).

Every batch lifecycle/outcome event is appended to the append-only, hash-chained
audit log via the existing privileged writer (R6). Attribution is honest:

  agent_id   = "bulk-worker"   (reserved slug — the async worker subsystem)
  tenant_id  = the SUBMITTING tenant (the real owner — NEVER WILDCARD_UUID; a
               batch belongs to a real tenant, so system attribution would lie)
  team_id / project_id = the submitting key's real team/project (carried on the job)
  action_taken = per the variant map (batch_file_blocked -> 'blocked', else 'logged')

Per-file SECURITY findings (pii_blocked / injection_detected / secret_leaked /
policy_decision_*) are emitted by the REUSED F-005/F-008 path with their existing
variants — these batch_* events are lifecycle/outcome meta-events on top.

emit_batch_event() appends via AuditLogRepository on a PRIVILEGED session the
CALLER supplies (append() asserts it — the chain is global, ADR-0005). Reusing
the caller's privileged session lets a worker action + its audit event share one
transaction where appropriate.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.audit_log_repository import AuditLogRepository

# Reserved agent_id slug for the async bulk worker principal (contracts/ids.md).
BULK_WORKER_PRINCIPAL = "bulk-worker"

# event_type -> action_taken (must match ACTION_TAKEN_BY_EVENT_TYPE + 0019 CHECK).
BATCH_EVENT_ACTION: dict[str, str] = {
    "batch_submitted": "logged",
    "batch_file_processed": "logged",
    "batch_file_blocked": "blocked",
    "batch_file_dead_lettered": "logged",
    "batch_completed": "logged",
}


def _now_rfc3339_z() -> str:
    """RFC3339 UTC with the 'Z' form (matches every production audit writer)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def emit_batch_event(
    session: AsyncSession,
    *,
    event_type: str,
    tenant_id: str,
    team_id: str,
    project_id: str,
    request_id: str,
) -> None:
    """Append a bulk-worker-attributed audit event on the caller's privileged session.

    Args:
        session: a PRIVILEGED session (get_privileged_session()); append() asserts it.
        event_type: one of BATCH_EVENT_ACTION.
        tenant_id: the SUBMITTING tenant (honest attribution — never WILDCARD_UUID).
        team_id / project_id: the submitting key's real team/project.
        request_id: correlation id (the batch's submit request id, or a worker id).

    Raises ValueError for a non-bulk event_type (defense-in-depth).
    """
    if event_type not in BATCH_EVENT_ACTION:
        raise ValueError(f"not a bulk event_type: {event_type!r}")

    event_data: dict[str, object] = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "event_timestamp": _now_rfc3339_z(),
        "request_id": request_id,
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": BULK_WORKER_PRINCIPAL,
        "action_taken": BATCH_EVENT_ACTION[event_type],
    }
    await AuditLogRepository(session).append(event_data)
