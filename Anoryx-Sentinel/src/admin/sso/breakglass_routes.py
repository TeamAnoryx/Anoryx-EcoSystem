"""Break-glass login audit endpoint (F-014 STEP 6, ADR-0017 §8 D7; vector 15, R5).

The env SENTINEL_ADMIN_TOKEN path is the IdP-down recovery / bootstrap path and is
NEVER removed (R5). Every break-glass LOGIN must be distinctly visible in the audit
log via a dedicated admin_breakglass_used event (separate from operator_sso_login).

This router is mounted UNDER admin_router, so require_admin gates it — the env token
IS the auth here, which is correct: only a holder of the break-glass token can emit
the break-glass-used signal. It is fail-closed by construction (no/invalid token ->
401 before this handler runs).

  POST /admin/breakglass/login  ->  {ok: true}

The console calls this ONCE at break-glass login (STEP 7 wires the call). Ordinary
admin API calls do NOT re-emit — this is the explicit login signal, not a per-request
marker.

Attribution (ADR-0017 §10):
  event_type   = admin_breakglass_used
  tenant_id    = WILDCARD_UUID (SYSTEM_TENANT_ID) — a system-scoped auth event with
                 no single target tenant (break-glass is cross-tenant by purpose).
  agent_id     = "admin-console" (the break-glass emitting principal slug).
  actor_id     = None (break-glass carries no per-operator identity).
  action_taken = "logged".

R6: the response carries NO tenant data and the audit row carries NO secret material
(never the token). The emit runs on a SEPARATE privileged session (append() asserts
the privileged role — the F-012a mutate-then-audit pattern).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, status

from admin.scope import reject_sso_global
from admin.sso.audit import ADMIN_CONSOLE_PRINCIPAL, emit_sso_event
from admin.util import request_id
from persistence.database import get_privileged_session
from policy.constants import WILDCARD_UUID

# break-glass is the env-token recovery path ONLY — an SSO operator-session must NEVER
# emit the system-scoped admin_breakglass_used signal (MED-1, audit-integrity; ADR §8 D7,
# vector 15). reject_sso_global -> SSO 403, break-glass allowed (require_admin still 401s
# an absent/invalid token at the parent router).
breakglass_router = APIRouter(
    tags=["admin", "sso", "breakglass"],
    dependencies=[Depends(reject_sso_global)],
)


@breakglass_router.post("/breakglass/login", status_code=status.HTTP_200_OK)
async def breakglass_login(request: Request) -> dict:
    """Emit the audited break-glass login signal. Returns {ok: true} only.

    Reachable only with a valid SENTINEL_ADMIN_TOKEN (require_admin at the parent
    router). No/invalid token -> 401 (fail-closed by construction). Emits exactly
    one admin_breakglass_used row (system-scoped, agent_id=admin-console,
    actor_id=None, action_taken='logged') on a privileged session. No tenant data
    is returned and no secret material is logged or audited (R6).
    """
    rid = request_id(request)
    async with get_privileged_session() as ps:
        async with ps.begin():
            await emit_sso_event(
                ps,
                event_type="admin_breakglass_used",
                target_tenant_id=WILDCARD_UUID,  # SYSTEM_TENANT_ID — no single tenant
                request_id=rid,
                agent_id=ADMIN_CONSOLE_PRINCIPAL,
                actor_id=None,
                action_taken="logged",
            )
    return {"ok": True}
