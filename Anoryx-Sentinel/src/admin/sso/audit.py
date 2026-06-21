"""SSO / operator audit emit helper (F-014, ADR-0017 §10 D9).

emit_sso_event() appends one of the four F-014 SSO/break-glass meta-events on the
caller's PRIVILEGED session (mirrors admin.audit.emit_admin_event — append() reads
the global chain tip and asserts the privileged role). Reused by STEP 3
(idp_config_changed) and by later steps (the SSO login/denied/break-glass paths).

HONEST ATTRIBUTION (D9, R6 — the vector-16 carrier):
  agent_id   — the emitting SUBSYSTEM slug: "operator-sso" for an SSO-authenticated
               operator, or "admin-console" for the env-token break-glass path.
  actor_id   — the SPECIFIC operator's admin_users.id (an opaque UUID, NOT PII —
               never the raw IdP subject/email/NameID). Included in the event_data
               dict ONLY when not None, so the hash-chain conditional
               canonicalization carries it for operator-attributed rows and omits
               it for break-glass / pre-binding rows.
  tenant_id  — NEVER nil-UUID for a tenant-bound event; WILDCARD_UUID
               (SYSTEM_TENANT_ID) is used ONLY for admin_breakglass_used and a
               pre-binding operator_sso_denied (where no tenant resolves yet).

R6: this helper NEVER carries secret material. idp_config_changed rows ride only
the canonical identity/chain fields — no client_secret, no private key, no
ciphertext, no protocol secret.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.audit_log_repository import AuditLogRepository
from policy.constants import WILDCARD_UUID

# Reserved emitting-principal slugs (contracts/ids.md). The SSO subsystem slug.
OPERATOR_SSO_PRINCIPAL = "operator-sso"
ADMIN_CONSOLE_PRINCIPAL = "admin-console"

# The four F-014 SSO/break-glass meta-event types (must match VALID_EVENT_TYPES +
# ACTION_TAKEN_BY_EVENT_TYPE, migration 0015, and contracts/events.schema.json).
SSO_EVENT_TYPES = frozenset(
    {
        "operator_sso_login",
        "operator_sso_denied",
        "admin_breakglass_used",
        "idp_config_changed",
    }
)


def _now_rfc3339_z() -> str:
    """RFC3339 UTC with the 'Z' form (matches every production audit writer)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


async def emit_sso_event(
    session: AsyncSession,
    *,
    event_type: str,
    target_tenant_id: str,
    request_id: str,
    agent_id: str,
    actor_id: str | None = None,
    action_taken: str = "logged",
    team_id: str = WILDCARD_UUID,
    project_id: str = WILDCARD_UUID,
) -> None:
    """Append an SSO/operator-attributed audit event on the caller's privileged session.

    Args:
        session: a PRIVILEGED session (get_privileged_session()); append() asserts
            it. The caller controls the transaction boundary.
        event_type: one of SSO_EVENT_TYPES.
        target_tenant_id: the tenant the action concerns. For idp_config_changed
            and operator_sso_login this is the TARGET / operator tenant (a real
            UUID, never WILDCARD). For admin_breakglass_used and a pre-binding
            operator_sso_denied, pass WILDCARD_UUID (SYSTEM_TENANT_ID).
        request_id: correlation id (^[A-Za-z0-9._-]{1,64}$).
        agent_id: the emitting principal slug — OPERATOR_SSO_PRINCIPAL
            ("operator-sso") or ADMIN_CONSOLE_PRINCIPAL ("admin-console"). For the
            STEP-3 break-glass idp_config_changed path this is "admin-console".
        actor_id: the operator's admin_users.id (opaque UUID). Included in the
            event_data dict ONLY when not None. None for break-glass. NEVER PII.
        action_taken: "logged" for login / break-glass / idp_config_changed;
            "blocked" for operator_sso_denied.
        team_id / project_id: WILDCARD_UUID for these tenant-level / system events.

    Raises ValueError for a non-SSO event_type (defense-in-depth).
    """
    if event_type not in SSO_EVENT_TYPES:
        raise ValueError(f"not an SSO event_type: {event_type!r}")

    event_data: dict[str, object] = {
        "event_id": str(uuid.uuid4()),
        "event_type": event_type,
        "event_timestamp": _now_rfc3339_z(),
        "request_id": request_id,
        "tenant_id": target_tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": agent_id,
        "action_taken": action_taken,
    }
    # actor_id is added ONLY when present, so the hash-chain canonicalization
    # carries it for operator-attributed rows and omits it otherwise (D9). The
    # value is the opaque admin_users.id — never PII, never a secret (R6).
    if actor_id is not None:
        event_data["actor_id"] = actor_id

    await AuditLogRepository(session).append(event_data)
