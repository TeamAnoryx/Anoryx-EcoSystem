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
# F-019 (ADR-0022 §5.4) adds three operator-action variants carrying a model_id in
# the `model` field — see migration 0027 + events_audit_log.VALID_EVENT_TYPES.
ADMIN_EVENT_TYPES = frozenset(
    {
        "admin_tenant_created",
        "admin_tenant_deactivated",
        "admin_key_minted",
        "admin_key_revoked",
        "admin_config_updated",
        "admin_audit_accessed",
        "model_approved",
        "model_denied",
        "model_adopted",
        # F-020 (ADR-0023 §5.4) — admin CRUD on a tenant's outbound webhook config.
        # Carries webhook_provider + config_action (created|updated|deleted); never
        # the target URL, credential, or signing-secret material (D1 — metadata-only).
        "webhook_config_updated",
        # F-021 (ADR-0024) — operator schedules / cancels model retirement (a grace
        # deadline on an approved model). Carries the model_id in `model`; the deadline
        # lives on the model_inventory row, not the event (action-only audit).
        "model_retirement_scheduled",
        "model_retirement_cancelled",
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
    actor_id: str | None = None,
    model: str | None = None,
    webhook_provider: str | None = None,
    config_action: str | None = None,
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
        actor_id: OPTIONAL per-operator attribution (F-014, ADR-0017 §10 D9). When
            an SSO operator performs an F-012a admin action, this is the operator's
            admin_users.id (an opaque UUID, NEVER PII). Included in the event_data
            dict ONLY when not None — so the hash-chain conditional canonicalization
            carries it for operator-attributed rows and omits it otherwise. The
            DEFAULT None reproduces the EXACT F-012a behavior (break-glass: NULL).
            agent_id stays "admin-console" for these F-012a meta-events (the slug
            names the subsystem; actor_id names the specific operator).

    Raises ValueError for a non-admin event_type (defense-in-depth).
    """
    if event_type not in ADMIN_EVENT_TYPES:
        raise ValueError(f"not an admin event_type: {event_type!r}")

    event_data: dict[str, object] = {
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
    # actor_id is added ONLY when present (D9): the hash-chain canonicalization
    # carries it for operator-attributed rows and omits it for break-glass / pre-
    # F-014 rows. The value is the opaque admin_users.id — never PII, never secret.
    if actor_id is not None:
        event_data["actor_id"] = actor_id
    # F-019 (ADR-0022 §5.4): the model identifier for model_approved/denied/adopted
    # rides in the existing `model` column (no new audit column). Added only when
    # provided so non-model admin events keep their exact prior canonical form.
    if model is not None:
        event_data["model"] = model
    # F-020 (ADR-0023 §5.4): webhook_config_updated carries the provider label and the
    # CRUD action. BOTH ride in dedicated nullable columns (migration 0030, hash-folded
    # by the repository) and are emitted under their EXACT contract field names —
    # contracts/events.schema.json WebhookConfigUpdatedEvent is additionalProperties:false
    # and lists webhook_provider + config_action as required, so the key names must match
    # (no violation_type passthrough). Both are bounded metadata labels — NEVER a URL,
    # credential, or signing-secret (D1/non-neg #6). Added only when provided so every
    # non-webhook admin event keeps its exact prior canonical form (no spurious null keys
    # in the historical hash chain).
    if webhook_provider is not None:
        event_data["webhook_provider"] = webhook_provider
    if config_action is not None:
        event_data["config_action"] = config_action
    await AuditLogRepository(session).append(event_data)
