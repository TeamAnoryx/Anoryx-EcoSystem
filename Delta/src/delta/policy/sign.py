"""ES256 compact-JWS signer for Delta budget-enforcement policies (D-005, ADR-0005 §5).

VENDORED, BYTE-IDENTICAL copy of Sentinel's ``policy.crypto`` canonicalization. Delta
signs the policy itself (the Orchestrator never signs — ADR-0004 Fork A); Sentinel's
``intake_policy()`` verifies. The signed payload MUST reproduce Sentinel's exact bytes:

  * payload = the eight ``SIGNED_CLAIM_FIELDS`` + ``policy_hash`` (SHA-256 of the
    canonical full record minus ``signature``);
  * canonical = ``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)``
    (the json default — NOT JCS RFC 8785; ADR-0009 §12.1 binds the future Delta signer
    to these exact bytes, including ``\\uXXXX`` non-ASCII escaping);
  * header = ``{"alg":"ES256","typ":"JWT"}``;
  * signature = ECDSA P-256 over ``header.payload``, raw 64-byte R‖S, base64url no pad.

A conformance test asserts the deterministic primitives here equal Sentinel's
``policy.crypto`` byte-for-byte and that a Delta signature verifies through Sentinel's
``verify_compact_jws`` (ECDSA is non-deterministic, so the signature string itself is
NOT compared — the round-trip is). If Sentinel's canonicalization migrates to JCS, that
test breaks and this module must follow.

Key custody: the P-256 PKCS#8 private key is injected via
``DELTA_POLICY_SIGNING_PRIVATE_KEY_PEM`` and loaded fail-closed (absent/empty/non-P256 =>
raise). Production HSM/KMS + rotation are deferred (ADR-0009 §12). No key material,
signature bytes, or raw payload is ever logged by this module.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

# --- Vendored constants (MUST equal Sentinel policy.constants; asserted by the
# conformance test). ---
_ALG = "ES256"
_TYP = "JWT"
_POINT_BYTES = 32  # P-256 field element size

# The eight authoritative scope claims carried inside the JWS payload (Sentinel
# SIGNED_CLAIM_FIELDS). Sentinel resolves authoritative scope from these, cross-checked
# against the record body.
SIGNED_CLAIM_FIELDS = (
    "tenant_id",
    "team_id",
    "project_id",
    "agent_id",
    "policy_id",
    "policy_version",
    "effective_from",
    "policy_type",
)
# The claim carrying a SHA-256 hash of the canonical full record (binds every field,
# including the enforcement-determining ones, to the signature).
CONTENT_HASH_CLAIM = "policy_hash"

# tenant_id may NEVER be the wildcard (cross-tenant blast radius; Sentinel intake rejects
# it). Delta refuses to sign such a record defensively (ADR-0005 §6, vector 8).
_WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"

_SIGNING_KEY_ENV = "DELTA_POLICY_SIGNING_PRIVATE_KEY_PEM"


class PolicySigningKeyError(RuntimeError):
    """The Delta signing key is missing/empty/invalid (fail-closed)."""


class PolicySignError(ValueError):
    """A record cannot be signed (e.g. a wildcard tenant)."""


# --------------------------------------------------------------------------- #
# Deterministic primitives — byte-identical to Sentinel policy.crypto
# --------------------------------------------------------------------------- #
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _der_to_raw(der: bytes) -> bytes:
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(_POINT_BYTES, "big") + s.to_bytes(_POINT_BYTES, "big")


def canonical_claims(claims: dict[str, Any]) -> bytes:
    """Deterministic claim serialization (sorted keys, no whitespace, UTF-8)."""
    return json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _encode_header() -> str:
    return _b64url_encode(
        json.dumps({"alg": _ALG, "typ": _TYP}, separators=(",", ":")).encode("utf-8")
    )


def extract_claims(record: dict[str, Any]) -> dict[str, Any]:
    """The eight authoritative scope claims pulled from a (complete) record."""
    return {field: record[field] for field in SIGNED_CLAIM_FIELDS}


def policy_content_hash(record: dict[str, Any]) -> str:
    """SHA-256 hex of the canonical record — EVERY field except ``signature``."""
    body = {k: v for k, v in record.items() if k != "signature"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def sign_claims(claims: dict[str, Any], private_key: EllipticCurvePrivateKey) -> str:
    """Produce a compact-JWS (ES256) over the canonical claims payload."""
    header_b64 = _encode_header()
    payload_b64 = _b64url_encode(canonical_claims(claims))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    sig_b64 = _b64url_encode(_der_to_raw(der))
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def sign_policy_record(
    record: dict[str, Any], private_key: EllipticCurvePrivateKey
) -> dict[str, Any]:
    """Return a copy of *record* with a fresh compact-JWS over its scope claims + hash.

    Refuses to sign a wildcard-tenant record (Sentinel intake would reject it; signing it
    would be a cross-tenant blast-radius footgun if the key leaked).
    """
    if record.get("tenant_id") == _WILDCARD_UUID:
        raise PolicySignError("refusing to sign a wildcard-tenant policy")
    signed = dict(record)
    claims = extract_claims(record)
    claims[CONTENT_HASH_CLAIM] = policy_content_hash(record)
    signed["signature"] = sign_claims(claims, private_key)
    return signed


# --------------------------------------------------------------------------- #
# Key (de)serialization + Delta key custody (env-injected, fail-closed)
# --------------------------------------------------------------------------- #
def load_private_key_pem(data: bytes) -> EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise PolicySigningKeyError("Delta signing private key must be ECDSA P-256 (secp256r1)")
    return key


def public_key_to_pem(public_key: EllipticCurvePublicKey) -> bytes:
    """SubjectPublicKeyInfo PEM (the form Sentinel POLICY_SIGNING_PUBKEY_PATH must hold)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_signing_key() -> EllipticCurvePrivateKey:
    """Load the Delta signing private key from the environment (fail-closed).

    Raises :class:`PolicySigningKeyError` when the env var is unset/empty or the value is
    not a P-256 PKCS#8 PEM. A missing key is a deployment/config error: the engine treats
    a sign failure as a PUBLISH failure (the decision is recorded in the outbox + alerted,
    never silently dropped and never fail-open — ADR-0005 §3.5).
    """
    raw = os.environ.get(_SIGNING_KEY_ENV, "")
    if not raw.strip():
        raise PolicySigningKeyError(
            f"{_SIGNING_KEY_ENV} is not set. This is the P-256 PKCS#8 PEM private key Delta "
            "uses to sign budget-enforcement policies. The engine refuses to sign without it "
            "(fail-closed). See Delta/.env.example."
        )
    try:
        return load_private_key_pem(raw.encode("utf-8"))
    except PolicySigningKeyError:
        raise
    except Exception as exc:  # malformed PEM, etc.
        raise PolicySigningKeyError(
            f"{_SIGNING_KEY_ENV} is set but the signing key could not be parsed"
        ) from exc
