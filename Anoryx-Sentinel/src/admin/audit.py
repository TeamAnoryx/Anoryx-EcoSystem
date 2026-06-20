"""Admin audit emission (F-012a, ADR-0014 §8/§9 D7/D8).

Every admin mutating action and every admin cross-tenant DATA read emits an
audit event attributing the action to the ADMIN principal + the TARGET tenant
(R1/R6):

  agent_id   = "admin-console"  (reserved slug — admin.auth.ADMIN_PRINCIPAL)
  tenant_id  = the TARGET tenant the operator acted upon
  team_id    = project_id = WILDCARD_UUID for tenant-level events (4th reserved
               use, contracts/ids.md); the key's real team/project for key events
  action_taken = "logged"

This is NEVER nil-UUID for tenant_id (that is system attribution) and NEVER the
target tenant's own agent_id (that would falsely claim the tenant acted).

emit_admin_event() appends via AuditLogRepository on a PRIVILEGED session the
CALLER supplies — so a mutating action and its audit event commit in one
transaction, and an audit-READ access event (D8) is a SEPARATE privileged append
distinct from the read's zero-write serving query.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from admin.auth import ADMIN_PRINCIPAL
from persistence.repositories.audit_log_repository import AuditLogRepository
from policy.constants import WILDCARD_UUID

# Admin event types (must match VALID_EVENT_TYPES + ck_eal_event_type, migration 0013).
ADMIN_EVENT_TYPES = frozenset(
    {
        "admin_tenant_created",
        "admin_tenant_deactivated",
        "admin_key_minted",
        "admin_key_revoked",
        "admin_config_updated",
        "admin_audit_accessed",
    }
)


def _now_rfc3339_z() -> str:
    """RFC3339 UTC with the 'Z' form (matches every production audit writer)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def emit_admin_event(
    session: AsyncSession,
    *,
    event_type: str,
    target_tenant_id: str,
    request_id: str,
    team_id: str = WILDCARD_UUID,
    project_id: str = WILDCARD_UUID,
) -> None:
    """Append an admin-attributed audit event on the caller's privileged session.

    Args:
        session: a PRIVILEGED session (get_privileged_session()); append() asserts
            it. Reusing the caller's session keeps the action + its event atomic.
        event_type: one of ADMIN_EVENT_TYPES.
        target_tenant_id: the tenant the admin acted upon (honest attribution).
        request_id: correlation id (TerminalAudit's req-... or a fresh one).
        team_id / project_id: WILDCARD_UUID for tenant-level events; the key's
            real team/project for key events.

    Raises ValueError for a non-admin event_type (defense-in-depth).
    """
    if event_type not in ADMIN_EVENT_TYPES:
        raise ValueError(f"not an admin event_type: {event_type!r}")

    event_data = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "event_timestamp": _now_rfc3339_z(),
        "request_id": request_id,
        "tenant_id": target_tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": ADMIN_PRINCIPAL,
        "action_taken": "logged",
    }
    await AuditLogRepository(session).append(event_data)
