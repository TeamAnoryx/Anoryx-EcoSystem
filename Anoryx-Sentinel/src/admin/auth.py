"""Admin authentication primitive (ADR-0014 D1, Affu STEP-0 fork (a)).

Env-token model: a single deploy-injected operator secret SENTINEL_ADMIN_TOKEN
guards every /admin/* route. This principal is DISTINCT from tenant Bearer auth
and acts ACROSS tenants — the first such principal in Sentinel (ADR-0014).

Security invariants (R2):
  - FAIL-CLOSED: if SENTINEL_ADMIN_TOKEN is unset/empty, every admin route returns
    401. There is NO fall-back to tenant scope and NO tenant data is ever exposed.
  - DISTINCT: this dependency validates ONLY against SENTINEL_ADMIN_TOKEN. It never
    consults the virtual-key path, so a tenant key presented on /admin is rejected.
  - CONSTANT-TIME: the token comparison uses hmac.compare_digest.

Provisioning: SENTINEL_ADMIN_TOKEN comes from Vault/KMS env at deploy
(CLAUDE.md non-negotiable #4) — never in code, config, logs, or tests.

The /admin/* paths are skipped by AuthMiddleware and TenantContextMiddleware
(they are not tenant-scoped); require_admin is the sole authority there.
"""

from __future__ import annotations

import hmac
import os

import structlog
from fastapi import HTTPException, Request

log = structlog.get_logger(__name__)

_ADMIN_TOKEN_ENV = "SENTINEL_ADMIN_TOKEN"  # noqa: S105 — env var NAME, not a secret

# Reserved agent_id slug for admin-attributed audit events (contracts/ids.md).
# Honest attribution (R6): admin actions carry this slug + the TARGET tenant_id —
# never nil-UUID (that is system attribution), never the tenant's own identity.
ADMIN_PRINCIPAL = "admin-console"

_UNAUTHORIZED = 401


def _get_admin_token() -> str | None:
    """Return the configured admin token, or None if unset/empty (fail-closed)."""
    token = os.environ.get(_ADMIN_TOKEN_ENV, "")
    return token or None


async def require_admin(request: Request) -> str:
    """FastAPI dependency authorizing an admin (operator) request.

    Returns the admin principal slug on success; raises HTTPException(401) on any
    failure. Records the principal on request.state.admin_principal so downstream
    handlers attribute audit events honestly.

    Fail-closed cases (all -> 401, no tenant fallback, no tenant data):
      - SENTINEL_ADMIN_TOKEN unset/empty
      - Authorization header absent or not "Bearer <token>"
      - token mismatch (constant-time compare)
    """
    configured = _get_admin_token()
    if not configured:
        log.info("admin_auth_unconfigured", path=request.url.path)
        raise HTTPException(status_code=_UNAUTHORIZED, detail="admin_unauthorized")

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        log.info("admin_auth_missing_bearer", path=request.url.path)
        raise HTTPException(status_code=_UNAUTHORIZED, detail="admin_unauthorized")

    presented = auth_header[len("Bearer ") :]
    # compare_digest is constant-time and safe on differing lengths. Both operands
    # are ASCII tokens. An empty presented token never matches a non-empty secret.
    if not presented or not hmac.compare_digest(presented, configured):
        log.info("admin_auth_failed", path=request.url.path)
        raise HTTPException(status_code=_UNAUTHORIZED, detail="admin_unauthorized")

    request.state.admin_principal = ADMIN_PRINCIPAL
    return ADMIN_PRINCIPAL
