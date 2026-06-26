"""ES256 access-token mint + verify (R-003 FORK A).

Uses **PyJWT** (a vetted library — banked ecosystem rule "no hand-rolled JWT/signature
verification", Sentinel ``pyproject``). The module is named ``tokens`` rather than ``jwt`` so it
never shadows the PyJWT package it imports.

ALG-CONFUSION DEFENSE (the central security property here):
  * ``algorithms=["ES256"]`` is an explicit allowlist on decode. A token with ``alg:none`` is
    rejected (none is not in the list); a token with ``alg:HS256`` is rejected (HS256 is not in
    the list) — so the classic confusion attack (forge an HS256 token using the PEM **public**
    key as the HMAC secret) cannot validate. PyJWT checks the header ``alg`` against the allowlist
    BEFORE using the key, matching Sentinel's "alg pinned, header checked first" posture.
  * The verifying key is supplied as an EC **public** key object, so it is never usable as an HMAC
    secret even if an HS path were reached.

FAIL-CLOSED: any verification failure — bad signature, expired, wrong issuer, malformed, missing
required claim, or an unexpected/closed-model violation (incl. ``token_use != access``) — raises
:class:`TokenVerificationError`. There is no path that returns an unverified or partially-verified
principal.
"""

from __future__ import annotations

import jwt
from pydantic import ValidationError

from .claims import ISSUER, AccessTokenClaims
from .keys import KeyMaterial

ALG = "ES256"

# Claims that MUST be present for a token to be considered well-formed.
_REQUIRED_CLAIMS = ["iss", "sub", "tenant_id", "scope", "token_use", "iat", "exp", "jti"]


class TokenVerificationError(Exception):
    """A token failed verification (fail-closed). Maps to 401 invalid_token at the edge."""


def mint(claims: AccessTokenClaims, key: KeyMaterial) -> str:
    """Sign an ES256 access token for the given claims."""
    payload = claims.model_dump()
    # ``roles`` is an array claim (never null on the wire): omit it if unset rather than emit null.
    # ``idp_subject`` is explicitly nullable (RESERVED O-010), so a null value is left in place.
    if payload.get("roles") is None:
        payload.pop("roles", None)
    return jwt.encode(payload, key.private_key, algorithm=ALG)


def verify(token: str, key: KeyMaterial) -> AccessTokenClaims:
    """Verify an ES256 access token and return its closed, validated claims (fail-closed).

    Verifies signature (ES256 only), expiry, issuer, and the presence of the required claims via
    PyJWT, then re-parses the payload into the closed :class:`AccessTokenClaims` model — which
    rejects any unexpected claim and enforces ``token_use == "access"`` (refresh-as-access
    confusion is blocked). Raises :class:`TokenVerificationError` on any failure.
    """
    try:
        decoded = jwt.decode(
            token,
            key.public_key,
            algorithms=[ALG],
            issuer=ISSUER,
            options={
                "require": _REQUIRED_CLAIMS,
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": False,  # S1: no aud claim — do not require/verify an audience.
            },
        )
    except jwt.PyJWTError as exc:  # base of every PyJWT failure — fail closed on all.
        raise TokenVerificationError(str(exc)) from exc

    try:
        return AccessTokenClaims(**decoded)
    except ValidationError as exc:
        raise TokenVerificationError("token claims failed the closed-schema check") from exc
