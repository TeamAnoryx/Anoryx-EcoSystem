"""ES256 signing-key material — env-injected, fail-closed (R-003 FORK A+D).

The Rendly access token is an ES256 (ECDSA P-256) JWT. The signing **private** key is
injected from the environment at startup (``RENDLY_JWT_PRIVATE_KEY_PEM``), mirroring the
Sentinel ``SENTINEL_ADMIN_TOKEN`` deploy-time-secret pattern. There is **no default key** and
**no in-repo key**: if the variable is absent, empty, unparseable, or not a P-256 key, loading
raises :class:`KeyConfigError` and the application refuses to start. The token endpoint can
therefore never sign with a fallback/empty key (fail-closed).

R-003 is both issuer and verifier in one process, so the verifying **public** key is derived
from the loaded private key (``private_key.public_key()``) — the private key never has to leave
the issuer. A future verify-only consumer (R-005 reading identity off the token) would inject
only the public key; that path is a documented seam and is NOT built here.

Curve is validated to secp256r1 (P-256) exactly, matching the Sentinel ES256 posture
(``Anoryx-Sentinel/src/policy/crypto.py``): an ES256 token signed with a non-P-256 key is a
configuration error, caught at load, not at first-sign.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Deploy-time secret. NEVER committed; lives in GitHub Secrets / Vault / root .env only.
PRIVATE_KEY_ENV = "RENDLY_JWT_PRIVATE_KEY_PEM"


class KeyConfigError(RuntimeError):
    """The ES256 signing key is missing or invalid — the service must not start."""


@dataclass(frozen=True)
class KeyMaterial:
    """Loaded ES256 key pair: the private key signs, the public key verifies."""

    private_key: EllipticCurvePrivateKey
    public_key: EllipticCurvePublicKey


def _require_p256_private(key: object) -> EllipticCurvePrivateKey:
    """Validate the loaded key is an ECDSA P-256 private key (the only ES256 key)."""
    if not isinstance(key, EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise KeyConfigError(
            "RENDLY_JWT signing key must be an ECDSA P-256 (secp256r1) private key"
        )
    return key


def load_key_material(pem: str | None = None) -> KeyMaterial:
    """Load the ES256 key material, fail-closed.

    Reads the PEM from ``pem`` if given, else from ``RENDLY_JWT_PRIVATE_KEY_PEM``. Any
    failure — absent, empty, unparseable, or wrong-curve — raises :class:`KeyConfigError`
    so the caller (app factory) aborts startup rather than running with no/forged signing.
    """
    raw = pem if pem is not None else os.environ.get(PRIVATE_KEY_ENV)
    if not raw or not raw.strip():
        raise KeyConfigError(
            f"{PRIVATE_KEY_ENV} is not set — the ES256 signing key is required (fail-closed)"
        )
    try:
        loaded = load_pem_private_key(raw.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise KeyConfigError("RENDLY_JWT signing key PEM is malformed or unreadable") from exc
    private_key = _require_p256_private(loaded)
    return KeyMaterial(private_key=private_key, public_key=private_key.public_key())
