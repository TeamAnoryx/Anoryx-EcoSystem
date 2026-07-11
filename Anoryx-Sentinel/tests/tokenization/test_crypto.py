"""Unit tests for F-033 token-vault AES-256-GCM crypto (no DB)."""

from __future__ import annotations

import base64
import os

import pytest

from tokenization.crypto import decrypt, encrypt, reset_key_cache_for_testing
from tokenization.exceptions import TokenizationError, TokenVaultKeyError


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("SENTINEL_TOKEN_VAULT_KEY", base64.b64encode(os.urandom(32)).decode())
    reset_key_cache_for_testing()
    yield
    reset_key_cache_for_testing()


def test_round_trip():
    ct = encrypt("4111111111111111")
    assert decrypt(ct) == "4111111111111111"


def test_ciphertext_hides_plaintext():
    ct = encrypt("sensitive-value")
    assert "sensitive-value" not in ct
    assert "sensitive-value" not in base64.b64decode(ct).decode("latin-1")


def test_fresh_nonce_per_encrypt():
    assert encrypt("same") != encrypt("same")


def test_tamper_fails_closed(monkeypatch):
    ct = encrypt("secret")
    raw = bytearray(base64.b64decode(ct))
    raw[-1] ^= 0x01
    tampered = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(TokenizationError):
        decrypt(tampered)


def test_missing_key_fails_closed(monkeypatch):
    monkeypatch.delenv("SENTINEL_TOKEN_VAULT_KEY", raising=False)
    reset_key_cache_for_testing()
    with pytest.raises(TokenVaultKeyError):
        encrypt("x")


def test_bad_key_length_fails_closed(monkeypatch):
    monkeypatch.setenv("SENTINEL_TOKEN_VAULT_KEY", base64.b64encode(os.urandom(16)).decode())
    reset_key_cache_for_testing()
    with pytest.raises(TokenVaultKeyError):
        encrypt("x")


def test_aad_round_trip():
    ct = encrypt("4111111111111111", aad=b"tenant:acme")
    assert decrypt(ct, aad=b"tenant:acme") == "4111111111111111"


def test_wrong_aad_fails_closed():
    """A blob bound to one tenant must not decrypt under another tenant's aad."""
    ct = encrypt("secret", aad=b"tenant:acme")
    with pytest.raises(TokenizationError):
        decrypt(ct, aad=b"tenant:evil")


def test_missing_aad_on_bound_blob_fails_closed():
    ct = encrypt("secret", aad=b"tenant:acme")
    with pytest.raises(TokenizationError):
        decrypt(ct)  # no aad
