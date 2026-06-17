"""Unit tests for ES256 compact-JWS crypto primitives (ADR-0009 §2). No DB."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from policy import crypto
from policy.crypto import CompactJWSError, InvalidSignature, PolicyKeyError


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_token(alg: str, claims: dict, sig: bytes = b"\x01" * 8) -> str:
    """Craft a structurally-3-segment compact-JWS with an arbitrary header alg."""
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    return f"{header}.{payload}.{_b64(sig)}"


_CLAIMS = {
    "tenant_id": "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6",
    "team_id": "7d9e2f3a-1234-5c6b-8def-0123456789ab",
    "project_id": "b3c4d5e6-abcd-1234-ef01-234567890abc",
    "agent_id": "gateway-core",
    "policy_id": "11111111-2222-3333-4444-555555555555",
    "policy_version": 1,
    "effective_from": "2026-06-17T00:00:00Z",
    "policy_type": "budget_limit",
}


def test_sign_verify_round_trip_returns_claims() -> None:
    priv, pub = crypto.generate_keypair()
    token = crypto.sign_claims(_CLAIMS, priv)
    assert token.count(".") == 2
    recovered = crypto.verify_compact_jws(token, pub)
    assert recovered == _CLAIMS


def test_wrong_key_rejected() -> None:
    signer_priv, _ = crypto.generate_keypair()
    _, other_pub = crypto.generate_keypair()
    token = crypto.sign_claims(_CLAIMS, signer_priv)
    with pytest.raises(InvalidSignature):
        crypto.verify_compact_jws(token, other_pub)


def test_malformed_token_two_segments_rejected() -> None:
    _, pub = crypto.generate_keypair()
    with pytest.raises(CompactJWSError):
        crypto.verify_compact_jws("only.two", pub)


def test_alg_none_rejected_before_key_use() -> None:
    _, pub = crypto.generate_keypair()
    token = _make_token("none", _CLAIMS)
    with pytest.raises(CompactJWSError):
        crypto.verify_compact_jws(token, pub)


def test_alg_hs256_confusion_rejected() -> None:
    _, pub = crypto.generate_keypair()
    token = _make_token("HS256", _CLAIMS)
    with pytest.raises(CompactJWSError):
        crypto.verify_compact_jws(token, pub)


def test_truncated_raw_signature_rejected() -> None:
    """A correctly-shaped token whose signature segment is not 64 raw bytes."""
    _, pub = crypto.generate_keypair()
    header = _b64(json.dumps({"alg": "ES256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps(_CLAIMS).encode())
    token = f"{header}.{payload}.{_b64(b'\x01' * 10)}"  # 10 bytes, not 64
    with pytest.raises(CompactJWSError):
        crypto.verify_compact_jws(token, pub)


def test_keygen_pem_round_trip() -> None:
    priv, pub = crypto.generate_keypair()
    priv_pem = crypto.private_key_to_pem(priv)
    pub_pem = crypto.public_key_to_pem(pub)
    assert b"BEGIN PRIVATE KEY" in priv_pem
    assert b"BEGIN PUBLIC KEY" in pub_pem
    # Re-load and prove a token signed by the reloaded private verifies under the
    # reloaded public (full DER<->raw + serialization round trip).
    reloaded_priv = crypto.load_private_key_pem(priv_pem)
    reloaded_pub = crypto.load_public_key_pem(pub_pem)
    token = crypto.sign_claims(_CLAIMS, reloaded_priv)
    assert crypto.verify_compact_jws(token, reloaded_pub) == _CLAIMS


def test_load_public_key_rejects_non_p256() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_pub_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(
            encoding=crypto.serialization.Encoding.PEM,
            format=crypto.serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(PolicyKeyError):
        crypto.load_public_key_pem(rsa_pub_pem)


def test_load_verifying_key_unset_returns_none(monkeypatch) -> None:
    monkeypatch.delenv("POLICY_SIGNING_PUBKEY_PATH", raising=False)
    crypto.reset_key_cache_for_testing()
    try:
        assert crypto.load_verifying_key() is None
    finally:
        crypto.reset_key_cache_for_testing()


def test_load_verifying_key_unreadable_path_crashes(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("POLICY_SIGNING_PUBKEY_PATH", str(tmp_path / "nope.pem"))
    crypto.reset_key_cache_for_testing()
    try:
        with pytest.raises(PolicyKeyError):
            crypto.load_verifying_key()
    finally:
        crypto.reset_key_cache_for_testing()


def test_load_verifying_key_valid_path(monkeypatch, tmp_path) -> None:
    _, pub = crypto.generate_keypair()
    pub_path = tmp_path / "pub.pem"
    pub_path.write_bytes(crypto.public_key_to_pem(pub))
    monkeypatch.setenv("POLICY_SIGNING_PUBKEY_PATH", str(pub_path))
    crypto.reset_key_cache_for_testing()
    try:
        loaded = crypto.load_verifying_key()
        assert isinstance(loaded, EllipticCurvePublicKey)
    finally:
        crypto.reset_key_cache_for_testing()
