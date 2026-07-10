"""Offline license validation (F-036, ADR-0041).

A Sentinel license is a signed claim set. It is signed by Anoryx's license
private key and verified — entirely OFFLINE — by the deployed Sentinel using only
the corresponding PUBLIC key. There is no phone-home: an air-gapped install can
validate its license with zero network access.

We deliberately reuse the EXACT ES256 compact-JWS scheme F-008 uses for policy
signing (`policy.crypto`) rather than inventing a license format — same
algorithm-confusion defence, same vetted primitives, no hand-rolled crypto (R3).

Required claims (all validated, fail-closed):
  license_id, customer, edition, issued_at, not_before, expires_at
Optional claims: features (list[str]), max_tenants (int).

Validation checks, in order, any failure raising `LicenseError`:
  1. ES256 signature verifies against the license public key.
  2. `not_before` <= now <= `expires_at` (with small clock-skew tolerance).
  3. all required claims present and well-typed.

The public key is loaded from `SENTINEL_LICENSE_PUBKEY_PATH` (fail-closed if unset
or unreadable — an install with no valid key cannot pretend to be licensed),
mirroring how the policy verifying key is loaded.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from airgap.exceptions import LicenseError, LicenseKeyError
from policy.crypto import (
    CompactJWSError,
    PolicyKeyError,
    load_public_key_pem,
    sign_claims,
    verify_compact_jws,
)

_PUBKEY_ENV = "SENTINEL_LICENSE_PUBKEY_PATH"
_SKEW = timedelta(minutes=5)
_REQUIRED_CLAIMS = ("license_id", "customer", "edition", "issued_at", "not_before", "expires_at")


@dataclass(frozen=True)
class ValidatedLicense:
    """A license whose signature and validity window have been verified."""

    license_id: str
    customer: str
    edition: str
    not_before: datetime
    expires_at: datetime
    features: frozenset[str] = field(default_factory=frozenset)
    max_tenants: int | None = None

    def has_feature(self, name: str) -> bool:
        return name in self.features


def sign_license(claims: dict, private_key: EllipticCurvePrivateKey) -> str:
    """Sign a license claim set (ES256 compact-JWS). For the license issuer only."""
    missing = [c for c in _REQUIRED_CLAIMS if c not in claims]
    if missing:
        raise LicenseError(f"license is missing required claims: {missing}")
    return sign_claims(claims, private_key)


def _parse_ts(claims: dict, key: str) -> datetime:
    raw = claims.get(key)
    if not isinstance(raw, str):
        raise LicenseError(f"license claim {key!r} must be an ISO-8601 string")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise LicenseError(f"license claim {key!r} is not a valid ISO-8601 timestamp") from exc
    # Treat a naive timestamp as UTC so comparison is always tz-aware.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _validate_claims(claims: dict, *, now: datetime) -> ValidatedLicense:
    missing = [c for c in _REQUIRED_CLAIMS if c not in claims]
    if missing:
        raise LicenseError(f"license is missing required claims: {missing}")

    not_before = _parse_ts(claims, "not_before")
    expires_at = _parse_ts(claims, "expires_at")
    if expires_at <= not_before:
        raise LicenseError("license expires_at must be after not_before")
    if now + _SKEW < not_before:
        raise LicenseError(f"license is not yet valid (starts {not_before.isoformat()})")
    if now - _SKEW > expires_at:
        raise LicenseError(f"license has expired (ended {expires_at.isoformat()})")

    features = claims.get("features", [])
    if not isinstance(features, list) or not all(isinstance(f, str) for f in features):
        raise LicenseError("license claim 'features' must be a list of strings")
    max_tenants = claims.get("max_tenants")
    if max_tenants is not None and not isinstance(max_tenants, int):
        raise LicenseError("license claim 'max_tenants' must be an integer")

    return ValidatedLicense(
        license_id=str(claims["license_id"]),
        customer=str(claims["customer"]),
        edition=str(claims["edition"]),
        not_before=not_before,
        expires_at=expires_at,
        features=frozenset(features),
        max_tenants=max_tenants,
    )


def verify_license(
    token: str,
    public_key: EllipticCurvePublicKey,
    *,
    now: datetime | None = None,
) -> ValidatedLicense:
    """Verify a license token OFFLINE and return the validated license. Fail-closed."""
    now = now or datetime.now(timezone.utc)
    try:
        claims = verify_compact_jws(token, public_key)
    except (CompactJWSError, InvalidSignature) as exc:
        raise LicenseError(f"license signature verification failed: {exc}") from exc
    return _validate_claims(claims, now=now)


def load_license_public_key() -> EllipticCurvePublicKey:
    """Load the license verifying key from SENTINEL_LICENSE_PUBKEY_PATH. Fail-closed."""
    path = os.environ.get(_PUBKEY_ENV)
    if not path:
        raise LicenseKeyError(
            f"{_PUBKEY_ENV} is not set — an air-gapped install must ship a license public key"
        )
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        return load_public_key_pem(data)
    except (OSError, PolicyKeyError, ValueError) as exc:
        raise LicenseKeyError(f"could not load license public key from {path!r}: {exc}") from exc


def verify_license_from_env(token: str, *, now: datetime | None = None) -> ValidatedLicense:
    """Convenience: load the pubkey from env, then verify. Fail-closed."""
    return verify_license(token, load_license_public_key(), now=now)
