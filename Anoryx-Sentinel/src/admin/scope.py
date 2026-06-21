"""Admin authorization scope enforcement (F-014 STEP 7, ADR-0017 §3 D2 — the R1 control).

require_admin AUTHENTICATES (who) and sets request.state.admin_auth. These
dependencies AUTHORIZE (what + where) and are applied as router-level dependencies
ON TOP of require_admin + validate_tenant_id_path — they NEVER change a route body
or engine logic (additive auth-layering only, R8).

THE TENANT-PIN (R1, the primary cross-tenant defense, ADR-0017 §3 D2.3):
  enforce_admin_scope, on the PER-TENANT routers (keys / audit / control / idp),
  reads request.state.admin_auth and the {tenant_id} path param:
    * kind == "sso":
        - REQUIRE admin_auth.tenant_id == path {tenant_id}, else 403 (vector 1: an
          operator authenticated via tenant A's IdP cannot act on tenant B).
        - ROLE GATE: tenant_auditor -> only safe methods (GET/HEAD/OPTIONS); a write
          (POST/PATCH/PUT/DELETE) -> 403. tenant_admin -> all methods.
    * kind == "breakglass": allow ANY tenant + ANY method (cross-tenant recovery,
      unchanged, R5).

GLOBAL TENANT-REGISTRY (ADR-0017 §3 D2.5): create/list/get/deactivate tenant are
inherently cross-tenant; in v1 they are BREAK-GLASS-ONLY (no SSO path is ever
cross-tenant). reject_sso_global rejects kind == "sso" with 403; break-glass allowed.

FAIL-CLOSED (R4): if request.state.admin_auth is missing (require_admin did not run
or set it) these dependencies 403 rather than allow — they never assume a principal.
RLS is the second layer (get_tenant_session(target) already scopes every query);
this pin is the FIRST, at the API edge, before any session opens.
"""

from __future__ import annotations

from fastapi import HTTPException, Request

from admin.auth import AUTH_KIND_BREAKGLASS, AUTH_KIND_SSO
from admin.util import validate_tenant_id_path

_FORBIDDEN = 403

# HTTP methods that never mutate state (the tenant_auditor allow-set).
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Role that may perform write methods on its own tenant.
_ROLE_TENANT_ADMIN = "tenant_admin"
_ROLE_TENANT_AUDITOR = "tenant_auditor"


def _admin_auth(request: Request) -> dict:
    """Return request.state.admin_auth, or 403 fail-closed if absent (R4).

    require_admin sets this on every successful auth. Its absence means the auth
    dependency did not run / did not authorize — deny rather than assume.
    """
    admin_auth = getattr(request.state, "admin_auth", None)
    if not isinstance(admin_auth, dict):
        raise HTTPException(status_code=_FORBIDDEN, detail="admin_forbidden")
    return admin_auth


def enforce_admin_scope(request: Request) -> None:
    """Per-tenant router guard: tenant-pin + role gate for SSO; allow break-glass.

    Applied as a router-level dependency on the per-tenant routers (keys / audit /
    control / idp), AFTER require_admin + validate_tenant_id_path. The {tenant_id}
    path param is re-validated here (UUID shape) so this guard is correct even if it
    is the first dependency to read the path.

    SSO (kind == "sso"):
      * 403 unless admin_auth.tenant_id == path tenant_id (vector 1 tenant-pin).
      * 403 for a write method when role == tenant_auditor (read-only role gate).
    Break-glass (kind == "breakglass"): allowed for any tenant + any method (R5).
    """
    # Re-validate the path tenant_id (defense-in-depth; raises 422 on non-UUID).
    tenant_id = validate_tenant_id_path(request.path_params.get("tenant_id", ""))

    admin_auth = _admin_auth(request)
    kind = admin_auth.get("kind")

    if kind == AUTH_KIND_BREAKGLASS:
        # Cross-tenant recovery path — unconstrained by tenant or role (R5/R8).
        return

    if kind == AUTH_KIND_SSO:
        # R1 tenant-pin: the operator may act ONLY on its own (token) tenant.
        if admin_auth.get("tenant_id") != tenant_id:
            raise HTTPException(status_code=_FORBIDDEN, detail="admin_tenant_pin")
        # Role gate: tenant_auditor is read-only; writes require tenant_admin.
        role = admin_auth.get("role")
        if role == _ROLE_TENANT_AUDITOR and request.method.upper() not in _SAFE_METHODS:
            raise HTTPException(status_code=_FORBIDDEN, detail="admin_role_readonly")
        # tenant_admin (and any future write-capable role) -> all methods allowed.
        return

    # Unknown / missing kind -> fail-closed (R4).
    raise HTTPException(status_code=_FORBIDDEN, detail="admin_forbidden")


def reject_sso_global(request: Request) -> None:
    """Global tenant-registry guard: break-glass only; reject SSO (ADR-0017 §3 D2.5).

    Applied as a router-level dependency on the GLOBAL tenants_router. Global
    tenant-registry mutations/reads are inherently cross-tenant and have NO SSO
    path in v1 (the invariant: no SSO-authenticated request is ever cross-tenant).
    SSO -> 403; break-glass -> allowed.
    """
    admin_auth = _admin_auth(request)
    if admin_auth.get("kind") == AUTH_KIND_SSO:
        raise HTTPException(status_code=_FORBIDDEN, detail="admin_global_breakglass_only")
    # break-glass (or any non-SSO authorized principal) -> allowed.
