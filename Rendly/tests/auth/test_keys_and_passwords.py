"""R-003 key loading (FORK A+D, fail-closed) + Argon2id credential hashing (FORK C)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from rendly.auth.keys import PRIVATE_KEY_ENV, KeyConfigError, load_key_material
from rendly.auth.passwords import dummy_verify, hash_password, verify_password

# Neutral non-secret test inputs (these are not credentials).
_INPUT_A = "fixture-input-alpha"
_INPUT_B = "fixture-input-bravo"


def _pem(curve: ec.EllipticCurve) -> str:
    key = ec.generate_private_key(curve)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")


def test_loads_a_valid_p256_pem() -> None:
    material = load_key_material(_pem(ec.SECP256R1()))
    assert isinstance(material.public_key.curve, ec.SECP256R1)


def test_missing_env_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PRIVATE_KEY_ENV, raising=False)
    with pytest.raises(KeyConfigError):
        load_key_material()


def test_empty_pem_fails_closed() -> None:
    with pytest.raises(KeyConfigError):
        load_key_material("   ")


def test_unparseable_pem_fails_closed() -> None:
    # Not PEM at all -> cryptography raises -> we fail closed (no signing with a bad key).
    with pytest.raises(KeyConfigError):
        load_key_material("this is not a key")


def test_wrong_curve_fails_closed() -> None:
    # A P-384 key is not an ES256 key — caught at load, not at first sign.
    with pytest.raises(KeyConfigError):
        load_key_material(_pem(ec.SECP384R1()))


def test_env_var_is_the_default_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PRIVATE_KEY_ENV, _pem(ec.SECP256R1()))
    material = load_key_material()
    assert isinstance(material.public_key.curve, ec.SECP256R1)


def test_password_hash_roundtrip() -> None:
    phc = hash_password(_INPUT_A)
    assert "argon2id" in phc  # Argon2id PHC string, never plaintext
    assert phc != _INPUT_A
    assert verify_password(phc, _INPUT_A) is True


def test_wrong_password_is_false() -> None:
    phc = hash_password(_INPUT_A)
    assert verify_password(phc, _INPUT_B) is False


def test_malformed_hash_is_false_not_raise() -> None:
    assert verify_password("not-a-phc-string", _INPUT_A) is False


def test_dummy_verify_is_always_false() -> None:
    # Runs one Argon2 verify (timing equalization) and never authenticates.
    assert dummy_verify(_INPUT_A) is False
