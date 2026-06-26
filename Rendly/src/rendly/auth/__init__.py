"""Rendly authentication (R-003) — self-contained OAuth2 + JWT.

Real ES256 token issuance, verification, and rotating-refresh against the LOCKED R-001 contract
and the R-002 domain types. The user lookup is the only fixture-backed part (the ``UserStore``
seam R-004 implements for real); the token cryptography and verify/refresh logic are real.
"""

from __future__ import annotations

from .claims import ISSUER, TOKEN_USE_ACCESS, AccessTokenClaims
from .errors import MESSAGES, STATUS, AuthError, ErrorCode
from .keys import KeyConfigError, KeyMaterial, load_key_material
from .passwords import hash_password, verify_password
from .refresh import (
    InMemoryRefreshTokenStore,
    RefreshError,
    RefreshInvalid,
    RefreshReuse,
    RefreshTokenStore,
    RotationResult,
)
from .service import AuthConfig, TokenService
from .store import (
    InMemoryUserStore,
    StoredCredential,
    UserStore,
    build_fixture_store,
)
from .tokens import TokenVerificationError, mint, verify

__all__ = [
    "ISSUER",
    "TOKEN_USE_ACCESS",
    "AccessTokenClaims",
    "AuthConfig",
    "AuthError",
    "ErrorCode",
    "InMemoryRefreshTokenStore",
    "InMemoryUserStore",
    "KeyConfigError",
    "KeyMaterial",
    "MESSAGES",
    "RefreshError",
    "RefreshInvalid",
    "RefreshReuse",
    "RefreshTokenStore",
    "RotationResult",
    "STATUS",
    "StoredCredential",
    "TokenService",
    "TokenVerificationError",
    "UserStore",
    "build_fixture_store",
    "hash_password",
    "load_key_material",
    "mint",
    "verify",
    "verify_password",
]
