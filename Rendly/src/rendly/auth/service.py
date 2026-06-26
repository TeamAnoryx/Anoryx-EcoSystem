"""TokenService — issuance (password + refresh grants) + revoke orchestration (R-003).

Ties the pieces together for the two LOCKED grants and the revoke endpoint:

  * ``password`` grant: look up the credential, constant-time Argon2id verify, mint an ES256
    access token + issue a rotating refresh token.
  * ``refresh_token`` grant: rotate the presented refresh token (reuse-detection inside the
    store), confirm the user still exists, mint a fresh access token + return the rotated refresh
    token.
  * ``revoke``: revoke the refresh token's family (idempotent).

Identity is derived ONLY from the stored ``User``/``Profile`` and (on refresh) the store record —
never from request input. The access token's ``tenant_id``/``sub``/``roles`` therefore cannot be
influenced by the caller. A bad username, a wrong password, and an invalid/expired/reused refresh
token all surface as the SAME generic 401 ``invalid_token`` (no user- or token-enumeration oracle).
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from ..user import User
from . import tokens
from .claims import ISSUER, TOKEN_USE_ACCESS, AccessTokenClaims
from .errors import AuthError, ErrorCode
from .keys import KeyMaterial
from .passwords import dummy_verify, verify_password
from .refresh import RefreshError, RefreshTokenStore
from .schemas import TokenResponse
from .store import UserStore

Clock = Callable[[], datetime]

# 15-minute access tokens (well under the contract's 1h ceiling); 14-day refresh window.
DEFAULT_ACCESS_TTL_SECONDS = 900
DEFAULT_REFRESH_TTL_SECONDS = 14 * 24 * 3600


@dataclass(frozen=True)
class AuthConfig:
    access_ttl_seconds: int = DEFAULT_ACCESS_TTL_SECONDS
    refresh_ttl_seconds: int = DEFAULT_REFRESH_TTL_SECONDS


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_jti() -> str:
    # token_urlsafe yields [A-Za-z0-9_-]; matches the jti charset ^[A-Za-z0-9._-]{1,64}$.
    return secrets.token_urlsafe(24)


class TokenService:
    """Issues, refreshes, and revokes Rendly tokens against the user + refresh stores."""

    def __init__(
        self,
        *,
        user_store: UserStore,
        refresh_store: RefreshTokenStore,
        key: KeyMaterial,
        config: AuthConfig | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._users = user_store
        self._refresh = refresh_store
        self._key = key
        self._config = config or AuthConfig()
        self._clock: Clock = clock or _utc_now

    def issue_password_grant(
        self, *, username: str | None, password: str | None, requested_scope: str | None
    ) -> TokenResponse:
        if not username or not password:
            raise AuthError(ErrorCode.INVALID_REQUEST)
        cred = self._users.get_credentials(username)
        if cred is None:
            # Equalize Argon2 work on the unknown-user path so timing does not leak existence.
            dummy_verify(password)
            raise AuthError(ErrorCode.INVALID_TOKEN)
        if not verify_password(cred.password_hash, password):
            raise AuthError(ErrorCode.INVALID_TOKEN)

        scopes = self._resolve_scopes(cred.granted_scopes, requested_scope)
        roles = (cred.profile.org_role.value,)
        access = self._mint_access(cred.user, scopes, roles)
        refresh = self._refresh.issue(
            user_id=cred.user.user_id,
            tenant_id=cred.user.tenant_id,
            scopes=scopes,
            roles=roles,
            ttl_seconds=self._config.refresh_ttl_seconds,
        )
        return self._response(access, scopes, refresh)

    def issue_refresh_grant(self, *, refresh_token: str | None) -> TokenResponse:
        if not refresh_token:
            raise AuthError(ErrorCode.INVALID_REQUEST)
        try:
            rotation = self._refresh.rotate(
                refresh_token, ttl_seconds=self._config.refresh_ttl_seconds
            )
        except RefreshError as exc:
            raise AuthError(ErrorCode.INVALID_TOKEN) from exc

        user = self._users.get_user(rotation.user_id, rotation.tenant_id)
        if user is None:
            raise AuthError(ErrorCode.INVALID_TOKEN)

        access = self._mint_access(user, rotation.scopes, rotation.roles)
        return self._response(access, rotation.scopes, rotation.new_token)

    def revoke(self, token: str | None) -> None:
        # Idempotent logout: unknown/empty token is a silent no-op (no existence leak).
        if token:
            self._refresh.revoke(token)

    # -- internals -------------------------------------------------------------------------

    def _resolve_scopes(self, granted: frozenset[str], requested: str | None) -> frozenset[str]:
        if requested is None:
            return granted
        asked = frozenset(requested.split())
        if not asked <= granted:
            # A request for a scope the user was not granted is a widening attempt -> reject.
            raise AuthError(ErrorCode.INVALID_REQUEST)
        return asked

    def _mint_access(self, user: User, scopes: frozenset[str], roles: tuple[str, ...]) -> str:
        iat = int(self._clock().timestamp())
        claims = AccessTokenClaims(
            iss=ISSUER,
            sub=user.user_id,
            tenant_id=user.tenant_id,
            scope=" ".join(sorted(scopes)),
            token_use=TOKEN_USE_ACCESS,
            iat=iat,
            exp=iat + self._config.access_ttl_seconds,
            jti=_new_jti(),
            roles=list(roles),
            idp_subject=None,
        )
        return tokens.mint(claims, self._key)

    def _response(self, access: str, scopes: frozenset[str], refresh: str) -> TokenResponse:
        return TokenResponse(
            access_token=access,
            token_type="Bearer",
            expires_in=self._config.access_ttl_seconds,
            refresh_token=refresh,
            scope=" ".join(sorted(scopes)),
        )
