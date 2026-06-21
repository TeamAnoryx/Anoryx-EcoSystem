"""Unit tests for admin.sso.secret_box — AES-256-GCM encrypt-at-rest (F-014 STEP 3, R6).

Pure-unit (no DB). Covers:
  - round-trip encrypt/decrypt (str and bytes input);
  - unique nonce per call (two encrypts of the same plaintext differ);
  - fail-closed when the key is unset (IdpSecretKeyError on encrypt/decrypt);
  - set-but-invalid key (bad base64 / wrong length) raises IdpSecretKeyError at load;
  - tamper detection (flipping a ciphertext byte -> InvalidTag on decrypt).

No plaintext, ciphertext, or key is ever asserted into a log. Test keys are
assembled at runtime via base64(os.urandom(32)) — never committed (R6 / the F-005
push-protection lesson).
"""

from __future__ import annotations

import base64
import os

import pytest
from cryptography.exceptions import InvalidTag

from admin.sso import secret_box
from admin.sso.secret_box import IdpSecretKeyError

_KEY_ENV = "SENTINEL_IDP_SECRET_KEY"


def _fresh_key_b64() -> str:
    """A valid base64-encoded 32-byte AES key assembled at runtime (never committed)."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


@pytest.fixture(autouse=True)
def _reset_secret_box_cache():
    """Reset the load-once cache before and after each test for isolation."""
    secret_box.reset_key_cache_for_testing()
    yield
    secret_box.reset_key_cache_for_testing()


def test_round_trip_str(monkeypatch):
    """A str plaintext encrypts and decrypts back to the original UTF-8 bytes."""
    monkeypatch.setenv(_KEY_ENV, _fresh_key_b64())
    plaintext = "super-secret-client-secret-value"
    blob = secret_box.encrypt(plaintext)
    assert isinstance(blob, bytes)
    assert blob != plaintext.encode("utf-8")  # stored form is NOT plaintext
    assert secret_box.decrypt(blob) == plaintext.encode("utf-8")


def test_round_trip_bytes(monkeypatch):
    """A bytes plaintext round-trips unchanged."""
    monkeypatch.setenv(_KEY_ENV, _fresh_key_b64())
    plaintext = os.urandom(64)
    assert secret_box.decrypt(secret_box.encrypt(plaintext)) == plaintext


def test_unique_nonce_per_call(monkeypatch):
    """Two encrypts of the same plaintext differ (fresh random nonce each time)."""
    monkeypatch.setenv(_KEY_ENV, _fresh_key_b64())
    plaintext = "the-same-input"
    a = secret_box.encrypt(plaintext)
    b = secret_box.encrypt(plaintext)
    assert a != b  # different nonce -> different blob
    # Both still decrypt to the same plaintext.
    assert secret_box.decrypt(a) == secret_box.decrypt(b) == plaintext.encode("utf-8")
    # The 12-byte nonce prefixes differ.
    assert a[:12] != b[:12]


def test_unset_key_fails_closed_on_encrypt(monkeypatch):
    """With the key unset, encrypt raises IdpSecretKeyError (config writes refuse)."""
    monkeypatch.delenv(_KEY_ENV, raising=False)
    with pytest.raises(IdpSecretKeyError):
        secret_box.encrypt("anything")


def test_unset_key_fails_closed_on_decrypt(monkeypatch):
    """With the key unset, decrypt also raises IdpSecretKeyError (fail-closed)."""
    monkeypatch.delenv(_KEY_ENV, raising=False)
    with pytest.raises(IdpSecretKeyError):
        secret_box.decrypt(b"\x00" * 32)


def test_invalid_base64_key_raises_at_load(monkeypatch):
    """A non-base64 key value raises IdpSecretKeyError on first use (deployment misconfig)."""
    monkeypatch.setenv(_KEY_ENV, "this-is-not-valid-base64!!!")
    with pytest.raises(IdpSecretKeyError):
        secret_box.encrypt("anything")


def test_wrong_length_key_raises_at_load(monkeypatch):
    """A base64 key that decodes to != 32 bytes raises IdpSecretKeyError at load."""
    short = base64.b64encode(os.urandom(16)).decode("ascii")  # AES-128 length, rejected
    monkeypatch.setenv(_KEY_ENV, short)
    with pytest.raises(IdpSecretKeyError):
        secret_box.encrypt("anything")


def test_tamper_ciphertext_byte_fails_decrypt(monkeypatch):
    """Flipping one ciphertext byte makes GCM authentication fail (InvalidTag)."""
    monkeypatch.setenv(_KEY_ENV, _fresh_key_b64())
    blob = bytearray(secret_box.encrypt("authenticated-payload"))
    # Flip a byte in the ciphertext/tag region (past the 12-byte nonce).
    blob[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        secret_box.decrypt(bytes(blob))


def test_tamper_nonce_byte_fails_decrypt(monkeypatch):
    """Flipping a nonce byte also fails authentication (the nonce is AAD-bound)."""
    monkeypatch.setenv(_KEY_ENV, _fresh_key_b64())
    blob = bytearray(secret_box.encrypt("authenticated-payload"))
    blob[0] ^= 0x01  # within the nonce prefix
    with pytest.raises(InvalidTag):
        secret_box.decrypt(bytes(blob))


def test_short_blob_raises_value_error(monkeypatch):
    """A blob too short to contain a nonce raises ValueError (not a silent guess)."""
    monkeypatch.setenv(_KEY_ENV, _fresh_key_b64())
    with pytest.raises(ValueError):
        secret_box.decrypt(b"\x00" * 8)  # < 12-byte nonce


def test_decrypt_with_different_key_fails(monkeypatch):
    """Ciphertext from key A does not decrypt under key B (InvalidTag)."""
    monkeypatch.setenv(_KEY_ENV, _fresh_key_b64())
    blob = secret_box.encrypt("bound-to-key-A")
    # Swap to a different key and reset the cache.
    secret_box.reset_key_cache_for_testing()
    monkeypatch.setenv(_KEY_ENV, _fresh_key_b64())
    with pytest.raises(InvalidTag):
        secret_box.decrypt(blob)
