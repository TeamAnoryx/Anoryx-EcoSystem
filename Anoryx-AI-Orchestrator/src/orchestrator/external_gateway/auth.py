"""X-Api-Key auth for the third-party external gateway (O-013, ADR-0013).

A DISTINCT credential from `require_tenant_principal` (O-006) — that credential
authenticates INTERNAL products/tenants (Bearer, `Authorization` header); this one
authenticates THIRD-PARTY callers (a dedicated `X-Api-Key` header), each key scoped to
exactly one tenant, one rate limit, and an explicit capability allow-list (`scopes`). Only
the SHA-256 hash of the presented key is ever computed/compared — the plaintext is never
stored or logged (mirrors `security.py`'s discipline exactly).

Resolution vs. authorization are deliberately split: this module ONLY resolves a
presented key to its full row (or raises a uniform 401 for a missing/malformed/unknown
key — no enumeration oracle). A REVOKED key still resolves here (its tenant IS known) —
whether a resolved-but-revoked key is rejected, and that rejection is chain-audited, is
the ROUTER's decision (external_gateway/router.py), not this module's, because only the
router knows the route being called and can attribute the audit link to it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from fastapi import Header

from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import get_third_party_api_key_by_hash

_KEY_HEADER = "X-Api-Key"


class ExternalGatewayAuthError(Exception):
    """Raised when a request lacks a valid third-party API key.

    The app installs an exception handler that renders this as a UNIFORM 401 (mirrors
    PrincipalAuthError). A missing header and an unknown key hash are indistinguishable —
    no enumeration oracle. NEVER raised for a revoked key (that resolves successfully
    here; the router 403s + chain-audits it instead — see module docstring).
    """


@dataclass(frozen=True, slots=True)
class ExternalGatewayPrincipal:
    """The resolved identity of a presented third-party API key."""

    key_id: str
    tenant_id: str
    scopes: tuple[str, ...]
    status: str
    rate_limit_per_minute: int


def _hash_key(presented: str) -> str:
    """SHA-256 hex of the presented X-Api-Key secret (the third_party_api_keys lookup key)."""
    return hashlib.sha256(presented.encode("utf-8")).hexdigest()


async def require_third_party_api_key(
    x_api_key: str | None = Header(default=None, alias=_KEY_HEADER),
) -> ExternalGatewayPrincipal:
    """FastAPI dependency -> the caller's resolved ExternalGatewayPrincipal.

    Extracts the `X-Api-Key` header, hashes it, and resolves it via
    `get_third_party_api_key_by_hash` on the PRIVILEGED session (the operator-global
    third_party_api_keys table is read before any tenant GUC is set — mirrors
    `require_tenant_principal` exactly). Absent/empty header or unknown hash ->
    ExternalGatewayAuthError -> a uniform 401. The plaintext key is never stored or logged.
    """
    if not x_api_key or not x_api_key.strip():
        raise ExternalGatewayAuthError()
    key_hash = _hash_key(x_api_key)
    async with get_privileged_session() as session:
        row = await get_third_party_api_key_by_hash(session, key_hash)
    if row is None:
        raise ExternalGatewayAuthError()
    return ExternalGatewayPrincipal(
        key_id=row["key_id"],
        tenant_id=row["tenant_id"],
        scopes=tuple(row["scopes"]),
        status=row["status"],
        rate_limit_per_minute=row["rate_limit_per_minute"],
    )
