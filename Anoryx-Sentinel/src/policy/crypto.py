"""ECDSA P-256 (ES256) compact-JWS sign/verify + verifying-key loading (ADR-0009 §2).

SECURITY PROPERTIES (design intent — not absolute claims):
  * alg is pinned to ES256. The header `alg` is checked BEFORE any key is used,
    so `alg:"none"` and `alg:"HS256"` (algorithm confusion, threat #3) are
    rejected up front — a symmetric verify against the EC public key is
    structurally impossible.
  * JWS ES256 signatures are raw 64-byte R‖S; `cryptography` produces/consumes
    DER. We convert on both sides (encode/decode_dss_signature). A signature
    whose raw form is not exactly 64 bytes is rejected before any curve math
    (threat #8, truncated signature).
  * The verifying public key is loaded ONCE from POLICY_SIGNING_PUBKEY_PATH and
    cached — never re-read per request (no TOCTOU). Env set-but-unreadable =>
    PolicyKeyError (caller crashes at startup, fail-closed misconfig, R3). Env
    unset => no key; every verify fails closed (caller returns RejectedSignature).
  * No secret material (PEM bytes, private key, signature bytes, raw payload) is
    ever logged by this module.

The signed payload is the eight-field scope claim set (constants.SIGNED_CLAIM_FIELDS),
serialized canonically (sorted keys, no whitespace) so signing is deterministic.
This is the AUTHORITATIVE scope; the record body IDs are a cross-check only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from policy.constants import CONTENT_HASH_CLAIM, SIGNED_CLAIM_FIELDS

_ALG = "ES256"
_TYP = "JWT"
_POINT_BYTES = 32  # P-256 field element size
_RAW_SIG_LEN = 64  # 32-byte R + 32-byte S
_POLICY_PUBKEY_ENV = "POLICY_SIGNING_PUBKEY_PATH"

# Re-export so callers (verify sites) can catch a single crypto-failure family.
__all__ = [
    "InvalidSignature",
    "CompactJWSError",
    "PolicyKeyError",
    "generate_keypair",
    "private_key_to_pem",
    "public_key_to_pem",
    "load_private_key_pem",
    "load_public_key_pem",
    "sign_claims",
    "sign_policy_record",
    "policy_content_hash",
    "verify_compact_jws",
    "extract_claims",
    "load_verifying_key",
    "reset_key_cache_for_testing",
]


class CompactJWSError(ValueError):
    """A compact-JWS token is structurally malformed or uses a forbidden alg."""


class PolicyKeyError(RuntimeError):
    """POLICY_SIGNING_PUBKEY_PATH is set but the key is unreadable/invalid (fail-closed)."""


# --------------------------------------------------------------------------- #
# base64url (no padding) helpers
# --------------------------------------------------------------------------- #
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except (ValueError, TypeError) as exc:  # binascii.Error subclasses ValueError
        raise CompactJWSError("invalid base64url segment") from exc


# --------------------------------------------------------------------------- #
# DER <-> raw R‖S signature conversion (JWS uses raw; cryptography uses DER)
# --------------------------------------------------------------------------- #
def _der_to_raw(der: bytes) -> bytes:
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(_POINT_BYTES, "big") + s.to_bytes(_POINT_BYTES, "big")


def _raw_to_der(raw: bytes) -> bytes:
    if len(raw) != _RAW_SIG_LEN:
        raise CompactJWSError(f"ES256 signature must be {_RAW_SIG_LEN} raw bytes")
    r = int.from_bytes(raw[:_POINT_BYTES], "big")
    s = int.from_bytes(raw[_POINT_BYTES:], "big")
    return utils.encode_dss_signature(r, s)


def canonical_claims(claims: dict[str, Any]) -> bytes:
    """Deterministic claim serialization (sorted keys, no whitespace, UTF-8)."""
    return json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _encode_header() -> str:
    return _b64url_encode(
        json.dumps({"alg": _ALG, "typ": _TYP}, separators=(",", ":")).encode("utf-8")
    )


# --------------------------------------------------------------------------- #
# Key generation / (de)serialization
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Generate a fresh ECDSA P-256 keypair (dev/test only; prod keys are HSM-managed)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def private_key_to_pem(private_key: EllipticCurvePrivateKey) -> bytes:
    """PKCS#8, unencrypted PEM. DEV/TEST ONLY — never persist a prod private key this way."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key: EllipticCurvePublicKey) -> bytes:
    """SubjectPublicKeyInfo PEM (the form POLICY_SIGNING_PUBKEY_PATH must point at)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(data: bytes) -> EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise PolicyKeyError("policy signing private key must be ECDSA P-256 (secp256r1)")
    return key


def load_public_key_pem(data: bytes) -> EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise PolicyKeyError("policy verifying public key must be ECDSA P-256 (secp256r1)")
    return key


# --------------------------------------------------------------------------- #
# Sign / verify
# --------------------------------------------------------------------------- #
def sign_claims(claims: dict[str, Any], private_key: EllipticCurvePrivateKey) -> str:
    """Produce a compact-JWS (ES256) over the canonical claims payload."""
    header_b64 = _encode_header()
    payload_b64 = _b64url_encode(canonical_claims(claims))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    sig_b64 = _b64url_encode(_der_to_raw(der))
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def extract_claims(record: dict[str, Any]) -> dict[str, Any]:
    """The eight authoritative scope claims pulled from a (complete) record."""
    return {field: record[field] for field in SIGNED_CLAIM_FIELDS}


def policy_content_hash(record: dict[str, Any]) -> str:
    """SHA-256 hex of the canonical record — EVERY field except `signature`.

    Canonical = sorted keys, no whitespace, UTF-8 (deterministic, order-independent).
    Binds the full policy body (including the enforcement-determining fields the
    eight scope claims do not cover) to the signature, so post-signing tampering of
    any field is detected at intake. Signers (the CLI now; Delta later) MUST use the
    same canonicalization.
    """
    body = {k: v for k, v in record.items() if k != "signature"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def sign_policy_record(
    record: dict[str, Any], private_key: EllipticCurvePrivateKey
) -> dict[str, Any]:
    """Return a copy of *record* with a fresh compact-JWS over its scope claims.

    The signed claims are the eight scope fields PLUS a content hash of the full
    record (CONTENT_HASH_CLAIM), so the signature covers the entire policy, not just
    the scope (ADR-0009 §2 / security hardening).
    """
    signed = dict(record)
    claims = extract_claims(record)
    claims[CONTENT_HASH_CLAIM] = policy_content_hash(record)
    signed["signature"] = sign_claims(claims, private_key)
    return signed


def verify_compact_jws(token: str, public_key: EllipticCurvePublicKey) -> dict[str, Any]:
    """Verify a compact-JWS and return its payload claims dict.

    Raises CompactJWSError (malformed / forbidden alg / truncated sig) or
    cryptography.exceptions.InvalidSignature (signature does not verify). Both
    are treated as a signature failure by the caller.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise CompactJWSError("compact JWS must have exactly three segments")
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
    except json.JSONDecodeError as exc:
        raise CompactJWSError("JWS header is not valid JSON") from exc
    if not isinstance(header, dict) or header.get("alg") != _ALG:
        # Algorithm-confusion defense: pin alg BEFORE touching the key.
        raise CompactJWSError(f"unsupported JWS alg; only {_ALG} is permitted")

    raw_sig = _b64url_decode(sig_b64)
    der = _raw_to_der(raw_sig)  # raises CompactJWSError if not 64 raw bytes
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))  # InvalidSignature on fail

    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except json.JSONDecodeError as exc:
        raise CompactJWSError("JWS payload is not valid JSON") from exc
    if not isinstance(claims, dict):
        raise CompactJWSError("JWS payload is not a JSON object")
    return claims


# --------------------------------------------------------------------------- #
# Verifying-key loader (load-once, fail-closed)
# --------------------------------------------------------------------------- #
_verifying_key: EllipticCurvePublicKey | None = None
_key_loaded = False


def load_verifying_key() -> EllipticCurvePublicKey | None:
    """Load (once, cached) the verifying public key from POLICY_SIGNING_PUBKEY_PATH.

    Returns the key, or None when the env var is unset (caller fails closed:
    every signature verification returns RejectedSignature). Raises PolicyKeyError
    when the env var is set but the file is unreadable / not a P-256 public key
    (the caller crashes at startup — a misconfigured signing key is a deployment
    error, not a runtime degrade; ADR-0009 §2, R3).
    """
    global _verifying_key, _key_loaded
    if _key_loaded:
        return _verifying_key

    path = os.environ.get(_POLICY_PUBKEY_ENV, "").strip()
    if not path:
        _key_loaded = True
        _verifying_key = None
        return None

    try:
        with open(path, "rb") as handle:
            data = handle.read()
        key = load_public_key_pem(data)
    except PolicyKeyError:
        raise
    except OSError as exc:
        raise PolicyKeyError(
            f"{_POLICY_PUBKEY_ENV} is set but the verifying key could not be read"
        ) from exc
    except Exception as exc:  # malformed PEM, etc.
        raise PolicyKeyError(
            f"{_POLICY_PUBKEY_ENV} is set but the verifying key could not be parsed"
        ) from exc

    _verifying_key = key
    _key_loaded = True
    return key


def reset_key_cache_for_testing() -> None:
    """Reset the load-once cache so a test can point at a fresh key path."""
    global _verifying_key, _key_loaded
    _verifying_key = None
    _key_loaded = False
