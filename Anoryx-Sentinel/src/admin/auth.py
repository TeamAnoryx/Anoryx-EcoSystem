"""Admin authentication primitive (ADR-0014 D1 + ADR-0017 §3 D2 — the auth boundary).

TWO bearer credentials are accepted on /admin/*, validated independently with NO
fall-through between them (mirrors ADR-0014 D1: a tenant key never elevates):

  1. BREAK-GLASS (env-token, ADR-0014, R5/R8 — UNCHANGED):
     a single deploy-injected SENTINEL_ADMIN_TOKEN, constant-time compared. This
     principal acts ACROSS tenants (its purpose is IdP-down recovery / bootstrap).
     On success request.state.admin_principal stays ADMIN_PRINCIPAL ("admin-console")
     and request.state.admin_auth = {kind:"breakglass", principal:"admin-console",
     tenant_id:None, role:None, admin_user_id:None}.

  2. SSO operator-session (ADR-0017 §3 D2 — ADDITIVE):
     an HMAC operator-session minted by admin.sso.session after a verified SSO
     assertion. On success request.state.admin_principal = "operator-sso" and
     request.state.admin_auth = {kind:"sso", principal:"operator-sso", tenant_id,
     role, admin_user_id} — carrying the operator's tenant-PIN + role so downstream
     enforce_admin_scope can enforce R1 (tenant isolation) + the role gate.

Security invariants (R2/R4/R5/R8):
  - FAIL-CLOSED: neither credential matches -> 401. No tenant fallback, no tenant
    data, no fall-through. If SENTINEL_ADMIN_TOKEN is unset AND the token is not a
    valid operator-session, the request is 401.
  - DISTINCT: this dependency validates ONLY the break-glass token and the
    operator-session. It never consults the virtual-key path, so a tenant key
    presented on /admin is rejected (a tenant key still never elevates).
  - MUTUALLY EXCLUSIVE: the break-glass compare is tried first; only on a miss is
    the operator-session verified. The env token is NEVER parsed as a session and
    a session is NEVER accepted as the env token (their shapes differ, and the
    constant-time env compare is exact). Both set request.state.admin_auth so
    downstream scope/role/attribution logic is uniform.
  - CONSTANT-TIME: the break-glass comparison uses hmac.compare_digest; the
    operator-session signature compare is constant-time inside session.verify.

Provisioning: SENTINEL_ADMIN_TOKEN + SENTINEL_ADMIN_SESSION_SECRET come from
Vault/KMS env at deploy (CLAUDE.md non-negotiable #4) — never in code/config/logs/
tests. R6: the token/secret/session are never logged.

The /admin/* paths are skipped by AuthMiddleware and TenantContextMiddleware
(they are not tenant-scoped); require_admin is the sole authority there.
"""

from __future__ import annotations

import hmac
import os

import structlog
from fastapi import HTTPException, Request

from admin.sso.session import OperatorSession, OperatorSessionError
from admin.sso.session import verify as verify_operator_session

log = structlog.get_logger(__name__)

_ADMIN_TOKEN_ENV = "SENTINEL_ADMIN_TOKEN"  # noqa: S105 — env var NAME, not a secret

# Reserved agent_id slug for admin-attributed audit events (contracts/ids.md).
# Honest attribution (R6): admin actions carry this slug + the TARGET tenant_id —
# never nil-UUID (that is system attribution), never the tenant's own identity.
ADMIN_PRINCIPAL = "admin-console"

# Reserved emitting-principal slug for SSO-operator-authenticated requests
# (contracts/ids.md, ADR-0017 §10 D9). request.state.admin_principal carries this
# for an SSO session; actor_id (the operator's admin_users.id) names the operator.
OPERATOR_SSO_PRINCIPAL = "operator-sso"

_UNAUTHORIZED = 401

# request.state.admin_auth kinds — downstream enforce_admin_scope dispatches on these.
AUTH_KIND_BREAKGLASS = "breakglass"
AUTH_KIND_SSO = "sso"


def _get_admin_token() -> str | None:
    """Return the configured admin token, or None if unset/empty (fail-closed)."""
    token = os.environ.get(_ADMIN_TOKEN_ENV, "")
    return token or None


def _set_breakglass_state(request: Request) -> None:
    """Record the break-glass principal on request.state (cross-tenant, no role)."""
    request.state.admin_principal = ADMIN_PRINCIPAL
    request.state.admin_auth = {
        "kind": AUTH_KIND_BREAKGLASS,
        "principal": ADMIN_PRINCIPAL,
        "tenant_id": None,
        "role": None,
        "admin_user_id": None,
    }


def _set_sso_state(request: Request, op: OperatorSession) -> None:
    """Record the SSO-operator principal on request.state (tenant-pinned + role)."""
    request.state.admin_principal = OPERATOR_SSO_PRINCIPAL
    request.state.admin_auth = {
        "kind": AUTH_KIND_SSO,
        "principal": OPERATOR_SSO_PRINCIPAL,
        "tenant_id": op.tenant_id,
        "role": op.role,
        "admin_user_id": op.admin_user_id,
    }


async def require_admin(request: Request) -> str:
    """FastAPI dependency authorizing an admin (operator) request.

    Accepts EITHER the break-glass env token (cross-tenant, R5/R8) OR an SSO
    operator-session (tenant-pinned, ADR-0017 §3 D2). Returns the principal slug on
    success and records request.state.admin_principal + request.state.admin_auth so
    downstream enforce_admin_scope can enforce the operator's tenant-pin + role and
    attribute audit honestly. Raises HTTPException(401) on any failure.

    Fail-closed cases (all -> 401, no tenant fallback, no tenant data):
      - Authorization header absent or not "Bearer <token>"
      - the token is neither the configured break-glass token NOR a valid
        operator-session (incl. when SENTINEL_ADMIN_TOKEN is unset/empty AND the
        token is not a valid session)
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        log.info("admin_auth_missing_bearer", path=request.url.path)
        raise HTTPException(status_code=_UNAUTHORIZED, detail="admin_unauthorized")

    presented = auth_header[len("Bearer ") :]
    if not presented:
        log.info("admin_auth_missing_bearer", path=request.url.path)
        raise HTTPException(status_code=_UNAUTHORIZED, detail="admin_unauthorized")

    # 1. BREAK-GLASS (env token) — tried first, constant-time. Behaviorally
    #    identical to the F-012a path: unconfigured token AND a wrong env token
    #    both fall through to the SSO attempt; only an exact match authorizes here.
    configured = _get_admin_token()
    if configured is not None and hmac.compare_digest(presented, configured):
        _set_breakglass_state(request)
        return ADMIN_PRINCIPAL

    # 2. SSO operator-session — only reached when the token is NOT the env token.
    #    A wrong-secret / malformed / expired session raises OperatorSessionError;
    #    an unset session secret also raises it (fail-closed, no fall-through).
    try:
        op = verify_operator_session(presented)
    except OperatorSessionError:
        log.info("admin_auth_failed", path=request.url.path)
        raise HTTPException(status_code=_UNAUTHORIZED, detail="admin_unauthorized") from None

    _set_sso_state(request, op)
    return OPERATOR_SSO_PRINCIPAL
