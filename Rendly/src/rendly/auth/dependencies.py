"""FastAPI verify dependency + scope gate (R-003 verification middleware).

``get_principal`` is the fail-closed verification seam every protected route depends on: it pulls
the Bearer token off the request, verifies it (ES256 signature, expiry, issuer, ``token_use``,
closed-claims), and yields the authoritative :class:`AccessTokenClaims`. EVERY failure — no
header, wrong scheme, empty token, or any verification error — raises ``AuthError(invalid_token)``
→ 401. There is no path that yields an unverified principal.

``require_scope`` builds a dependency that additionally checks the token carries the endpoint's
required scope, else ``AuthError(forbidden)`` → 403. Identity (tenant/user/roles) is read SOLELY
from the verified token, so a request body can never widen it (claim-injection defense).
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request

from .claims import AccessTokenClaims
from .errors import AuthError, ErrorCode
from .tokens import TokenVerificationError, verify

_BEARER_PREFIX = "Bearer "


def get_principal(request: Request) -> AccessTokenClaims:
    """Verify the request's Bearer access token and return its claims, or 401 (fail-closed)."""
    header = request.headers.get("Authorization")
    if not header or not header.startswith(_BEARER_PREFIX):
        raise AuthError(ErrorCode.INVALID_TOKEN)
    token = header[len(_BEARER_PREFIX) :].strip()
    if not token:
        raise AuthError(ErrorCode.INVALID_TOKEN)
    try:
        return verify(token, request.app.state.key_material)
    except TokenVerificationError as exc:
        raise AuthError(ErrorCode.INVALID_TOKEN) from exc


def require_scope(scope: str) -> Callable[..., AccessTokenClaims]:
    """Build a dependency that requires ``scope`` to be present in the verified token."""

    def _dependency(
        principal: AccessTokenClaims = Depends(get_principal),
    ) -> AccessTokenClaims:
        if scope not in principal.scope_set():
            raise AuthError(ErrorCode.FORBIDDEN)
        return principal

    return _dependency
