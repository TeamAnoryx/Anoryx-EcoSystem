"""Per-tenant authenticated principal for the read/query/distribution seams (O-006, ADR-0006).

The Orchestrator's first per-tenant authorization boundary. Every existing credential (the
ingest HMAC, the peer `ORCH_SERVICE_TOKEN`, the operator `ORCH_ADMIN_TOKEN`) is a single
SHARED coarse secret carrying NO tenant identity — so "validate tenant_id against the
principal" was not expressible. O-006 introduces a per-tenant service token
(`query_service_tokens`): a presented Bearer secret hashes to a row that maps it to a
`tenant_id`. `require_tenant_principal` is the shared FastAPI dependency that resolves that
principal; every tenant-scoped seam (the query/bus reads AND the distribution GET/POST) depends
on it, then runs the actual read under `get_tenant_session(principal)` so RLS is the structural
enforcer.

The coarse `ORCH_SERVICE_TOKEN` NO LONGER grants tenant-data reads on these seams — a per-tenant
token is required (the intended tightening; the coarse token had no legitimate cross-tenant read
grant). mTLS provisioning stays deferred to O-008; the interim Bearer is now tenant-bound.

Only the SHA-256 hash of the presented token is ever computed/compared — the plaintext is never
stored or logged. Missing header, malformed header, unknown token, and disabled token are ALL
mapped to a uniform 401 (no enumeration oracle: a caller cannot distinguish "no such token" from
"disabled" from "malformed").
"""

from __future__ import annotations

import hashlib

from fastapi import Header

from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import resolve_principal_tenant

_BEARER_PREFIX = "Bearer "


class PrincipalAuthError(Exception):
    """Raised when a request lacks a valid per-tenant service-token principal.

    The app installs an exception handler that renders this as a UNIFORM 401 using the standard
    error envelope. Distinct from the app's catch-all 503 handler (a specific handler wins over
    the `Exception` handler), so an auth miss is a clean 401, never a 503.
    """


def _hash_token(presented: str) -> str:
    """SHA-256 hex of the presented Bearer secret (the query_service_tokens lookup key)."""
    return hashlib.sha256(presented.encode("utf-8")).hexdigest()


async def require_tenant_principal(authorization: str | None = Header(default=None)) -> str:
    """FastAPI dependency → the caller's tenant principal (tenant_id) from a Bearer token.

    Extracts the Bearer secret, hashes it, and resolves it to a tenant_id via
    `resolve_principal_tenant` on the PRIVILEGED session (the operator-global
    query_service_tokens table is read before any tenant GUC is set). Returns the tenant_id.
    Any failure — absent/malformed/empty header, unknown token, disabled token — raises
    PrincipalAuthError → a uniform 401. The plaintext token is never stored or logged.
    """
    if not authorization or not authorization.startswith(_BEARER_PREFIX):
        raise PrincipalAuthError()
    presented = authorization[len(_BEARER_PREFIX) :]
    if not presented:
        raise PrincipalAuthError()
    token_sha256 = _hash_token(presented)
    async with get_privileged_session() as session:
        tenant_id = await resolve_principal_tenant(session, token_sha256)
    if tenant_id is None:
        raise PrincipalAuthError()
    return tenant_id
