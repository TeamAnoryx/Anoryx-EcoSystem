"""Admin API router (F-012a, ADR-0014).

All /admin/* routes are mounted under a single APIRouter whose router-level
dependency is require_admin — so EVERY admin route is auth-gated by construction
(fail-closed). Tenant lifecycle, key management, audit read, and the operator
control surface are added to this router in later steps.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from admin.audit_log import audit_log_router
from admin.auth import ADMIN_PRINCIPAL, require_admin
from admin.control import control_router
from admin.keys import keys_router
from admin.shadow_ai import shadow_ai_router
from admin.sso.breakglass_routes import breakglass_router
from admin.sso.idp_routes import idp_router
from admin.tenants import tenants_router

admin_router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


@admin_router.get("/whoami")
async def whoami(request: Request) -> dict[str, str]:
    """Return the authenticated admin principal (honest per-session).

    Reports the REAL principal slug set by require_admin on request.state:
    "admin-console" for the env-token break-glass path, "operator-sso" for an
    SSO operator-session (LOW fix — never mislabel an SSO session as break-glass).
    Reachable only with a valid credential (require_admin at the parent router),
    and only because the tenant middlewares skip the /admin prefix.
    """
    return {"principal": getattr(request.state, "admin_principal", ADMIN_PRINCIPAL)}


# Feature routers — each mounted under /admin with the require_admin dependency
# applied at the parent (so every admin route is auth-gated by construction).
admin_router.include_router(tenants_router)
admin_router.include_router(keys_router)
admin_router.include_router(audit_log_router)
admin_router.include_router(shadow_ai_router)
admin_router.include_router(control_router)
admin_router.include_router(idp_router)
admin_router.include_router(breakglass_router)
