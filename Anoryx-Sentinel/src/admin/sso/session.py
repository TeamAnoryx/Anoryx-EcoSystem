"""Operator-session token — mint + verify (F-014 STEP 7, ADR-0017 §3 D2 / §9 D8).

THE AUTH BOUNDARY. After a successful SSO assertion + group→role resolution
(finalize_sso_login), the admin API mints a compact signed operator-session token
that the console carries inside the existing F-012 cookie spine and forwards via
the BFF. The admin API independently VERIFIES it on every /admin call and enforces
the operator's tenant-pin + role (the R1 cross-tenant defense).

TOKEN SHAPE (mirrors frontend/src/lib/session-token.ts on the Python side):
  token = base64url(payload_json) "." base64url(HMAC-SHA256(payload_b64, secret))
  payload = {tenant_id, admin_user_id, role, auth_method:"sso", iat, exp, jti}

HMAC (symmetric) is correct here: the SAME admin API both mints and verifies — no
asymmetric trust is needed (ADR-0017 §3 D2.1). We do NOT reuse the ES256
policy-signing keypair (that exists for an EXTERNAL signer).

SECRET (R6, fail-closed mirroring policy.crypto / secret_box load-once):
  SENTINEL_ADMIN_SESSION_SECRET — Vault/KMS-injected at deploy. DISTINCT from the
  break-glass SENTINEL_ADMIN_TOKEN and from the frontend SESSION_SECRET. Loaded
  ONCE and cached. Unset -> mint/verify raise OperatorSessionError (fail-closed);
  module import never crashes on an unset secret (so unrelated admin routes still
  import) — the failure is deferred to the point of use.

SECURITY INVARIANTS:
  * verify() compares the signature in CONSTANT TIME (hmac.compare_digest) over the
    base64 signature segment, recomputed from the presented payload segment.
  * Expired (exp <= now), malformed (wrong segment count / bad base64 / bad JSON /
    missing claim / wrong auth_method), or wrong-secret tokens are REJECTED
    (OperatorSessionError) — never a partial / guessed claim set (fail-closed, R4).
  * TTL is bounded to <= 30 min (matches the cookie spine).
  * This module NEVER logs the token, the secret, the signature, or the payload (R6).
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from hashlib import sha256

_SESSION_SECRET_ENV = "SENTINEL_ADMIN_SESSION_SECRET"  # noqa: S105 — env var NAME, not a secret

# TTL bounded to 30 minutes (ADR-0017 §3 D2.1 "short TTL ≤30 min, matching the cookie").
SESSION_TTL_SECONDS = 30 * 60

# Fixed auth_method discriminator carried in the payload — an operator-session is
# ALWAYS auth_method="sso". A token missing or carrying a different value is rejected.
_AUTH_METHOD_SSO = "sso"

__all__ = [
    "OperatorSession",
    "OperatorSessionError",
    "SESSION_TTL_SECONDS",
    "mint",
    "verify",
    "reset_secret_cache_for_testing",
]


class OperatorSessionError(Exception):
    """An operator-session could not be minted or verified (fail-closed, R4).

    Raised when SENTINEL_ADMIN_SESSION_SECRET is unset (mint/verify refuse), or
    when a presented token is malformed / expired / signature-invalid. Carries no
    secret material and is never logged with the token attached (R6).
    """


@dataclass(frozen=True)
class OperatorSession:
    """The verified claims of an operator-session (the authorization principal).

    tenant_id is the operator's tenant-pin (the R1 control: the operator may act
    ONLY on this tenant). admin_user_id is the internal admin_users.id (the
    actor_id attribution carrier, D9). role is the highest mapped role.
    """

    tenant_id: str
    admin_user_id: str
    role: str
    auth_method: str
    iat: int
    exp: int
    jti: str


# --------------------------------------------------------------------------- #
# Load-once, fail-closed secret loader (mirrors secret_box._load_key /
# policy.crypto.load_verifying_key).
# --------------------------------------------------------------------------- #
_secret: bytes | None = None
_secret_loaded = False


def _load_secret() -> bytes:
    """Load (once, cached) the HMAC secret from SENTINEL_ADMIN_SESSION_SECRET.

    Raises OperatorSessionError when the env var is unset/empty (so mint and
    verify refuse — fail-closed, never minting/accepting an unsigned-equivalent
    token). The secret bytes are never logged.
    """
    global _secret, _secret_loaded
    if _secret_loaded:
        if _secret is None:
            raise OperatorSessionError(
                f"{_SESSION_SECRET_ENV} is not set; operator-session mint/verify is "
                "unavailable (fail-closed)."
            )
        return _secret

    raw = os.environ.get(_SESSION_SECRET_ENV, "").strip()
    if not raw:
        # Cache the unset state so the next call still fails-closed without a
        # re-read; reset_secret_cache_for_testing is required to pick up a later set.
        _secret = None
        _secret_loaded = True
        raise OperatorSessionError(
            f"{_SESSION_SECRET_ENV} is not set; operator-session mint/verify is "
            "unavailable (fail-closed)."
        )

    _secret = raw.encode("utf-8")
    _secret_loaded = True
    return _secret


# --------------------------------------------------------------------------- #
# base64url (no padding) helpers
# --------------------------------------------------------------------------- #
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _sign(payload_b64: str, secret: bytes) -> str:
    """base64url(HMAC-SHA256(payload_b64, secret)) — the signature segment."""
    mac = hmac.new(secret, payload_b64.encode("ascii"), sha256).digest()
    return _b64url_encode(mac)


# --------------------------------------------------------------------------- #
# Mint / verify
# --------------------------------------------------------------------------- #
def mint(principal, now: int | None = None) -> str:
    """Mint an operator-session token for a ProvisionedPrincipal.

    Args:
        principal: a ProvisionedPrincipal (carries tenant_id, admin_user_id, role).
            Accepted by duck typing (the import stays one-directional).
        now: optional epoch seconds (test hook); defaults to time.time().

    Returns:
        The compact token base64url(payload).base64url(HMAC-SHA256(payload, secret)).

    Raises:
        OperatorSessionError: SENTINEL_ADMIN_SESSION_SECRET is unset (fail-closed).
    """
    secret = _load_secret()
    iat = int(now if now is not None else time.time())
    payload = {
        "tenant_id": principal.tenant_id,
        "admin_user_id": principal.admin_user_id,
        "role": principal.role,
        "auth_method": _AUTH_METHOD_SSO,
        "iat": iat,
        "exp": iat + SESSION_TTL_SECONDS,
        "jti": uuid.uuid4().hex,
    }
    payload_b64 = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    return f"{payload_b64}.{_sign(payload_b64, secret)}"


def verify(token: str, now: int | None = None) -> OperatorSession:
    """Verify an operator-session token and return its claims, or raise.

    Constant-time signature compare (hmac.compare_digest on the base64 signature
    segment, recomputed from the presented payload). Rejects expired (exp <= now),
    malformed (segment count / base64 / JSON / missing claim / wrong auth_method),
    and signature-invalid (incl. wrong-secret) tokens. Never returns a partial
    claim set (fail-closed, R4).

    Args:
        token: the presented operator-session token.
        now: optional epoch seconds (test hook); defaults to time.time().

    Returns:
        OperatorSession on success.

    Raises:
        OperatorSessionError: unset secret, or any malformed/expired/forged token.
    """
    secret = _load_secret()
    if not token or not isinstance(token, str):
        raise OperatorSessionError("malformed operator-session token")

    dot = token.find(".")
    if dot <= 0 or dot == len(token) - 1:
        raise OperatorSessionError("malformed operator-session token")
    payload_b64 = token[:dot]
    provided_sig = token[dot + 1 :]

    # Constant-time signature compare over the base64 segment (recomputed from the
    # presented payload). compare_digest is safe on differing lengths.
    expected_sig = _sign(payload_b64, secret)
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise OperatorSessionError("operator-session signature mismatch")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, TypeError) as exc:  # binascii.Error subclasses ValueError
        raise OperatorSessionError("operator-session payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise OperatorSessionError("operator-session payload is not a JSON object")

    if payload.get("auth_method") != _AUTH_METHOD_SSO:
        raise OperatorSessionError("operator-session auth_method is not 'sso'")

    try:
        tenant_id = str(payload["tenant_id"])
        admin_user_id = str(payload["admin_user_id"])
        role = str(payload["role"])
        iat = int(payload["iat"])
        exp = int(payload["exp"])
        jti = str(payload["jti"])
    except (KeyError, TypeError, ValueError) as exc:
        raise OperatorSessionError("operator-session payload is missing a claim") from exc

    # Reject a nonsensical time window (exp at or before iat). A well-formed token
    # minted by mint() always has exp == iat + SESSION_TTL_SECONDS (> iat); an
    # exp <= iat indicates a forged/corrupt payload, so fail-closed (R4).
    if exp <= iat:
        raise OperatorSessionError("operator-session time window is invalid (exp <= iat)")

    current = int(now if now is not None else time.time())
    if exp <= current:
        raise OperatorSessionError("operator-session is expired")

    return OperatorSession(
        tenant_id=tenant_id,
        admin_user_id=admin_user_id,
        role=role,
        auth_method=_AUTH_METHOD_SSO,
        iat=iat,
        exp=exp,
        jti=jti,
    )


def reset_secret_cache_for_testing() -> None:
    """Reset the load-once cache so a test can point at a fresh secret (or unset)."""
    global _secret, _secret_loaded
    _secret = None
    _secret_loaded = False
