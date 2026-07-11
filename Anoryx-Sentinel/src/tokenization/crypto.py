"""AES-256-GCM encrypt-at-rest for the F-033 token vault (ADR-0039).

Mirrors admin/sso/secret_box.py's discipline: a 32-byte AES key loaded once
from SENTINEL_TOKEN_VAULT_KEY (base64 of exactly 32 bytes), fail-closed
(tokenize/detokenize refuse rather than store/return plaintext without
encryption), never logged. Blob layout is `nonce ‖ AESGCM.encrypt(...)` with a
fresh 12-byte random nonce per encrypt (GCM nonce reuse under one key is
catastrophic). No hand-rolled crypto (R3).
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tokenization.exceptions import TokenizationError, TokenVaultKeyError

_KEY_ENV = "SENTINEL_TOKEN_VAULT_KEY"  # noqa: S105 — env var NAME, not a secret
_KEY_BYTES = 32
_NONCE_BYTES = 12

_key: bytes | None = None
_key_loaded = False


def _load_key() -> bytes:
    global _key, _key_loaded
    if _key_loaded:
        if _key is None:
            raise TokenVaultKeyError(
                f"{_KEY_ENV} is not set; token-vault encryption unavailable "
                "(fail-closed — tokenize/detokenize refuse)."
            )
        return _key

    raw = os.environ.get(_KEY_ENV, "").strip()
    if not raw:
        _key, _key_loaded = None, True
        raise TokenVaultKeyError(f"{_KEY_ENV} is not set (fail-closed).")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, TypeError) as exc:
        _key, _key_loaded = None, True
        raise TokenVaultKeyError(f"{_KEY_ENV} is set but is not valid base64") from exc
    if len(decoded) != _KEY_BYTES:
        _key, _key_loaded = None, True
        raise TokenVaultKeyError(
            f"{_KEY_ENV} must decode to exactly {_KEY_BYTES} bytes (AES-256), got {len(decoded)}"
        )
    _key, _key_loaded = decoded, True
    return _key


def reset_key_cache_for_testing() -> None:
    global _key, _key_loaded
    _key, _key_loaded = None, False


def encrypt(plaintext: str, *, aad: bytes | None = None) -> str:
    """Return base64(nonce ‖ ciphertext‖tag) for a plaintext string.

    `aad` (associated data) is authenticated but not encrypted; decrypt() must be
    given the SAME aad or it fails closed. The token service binds the tenant_id
    here so a ciphertext blob only decrypts in its own tenant's context (a
    defence-in-depth complement to RLS — a blob lifted to another tenant/row will
    not authenticate even if DB-layer isolation is ever weakened).
    """
    key = _load_key()
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt(blob_b64: str, *, aad: bytes | None = None) -> str:
    """Reverse encrypt(). Raises on wrong key / tamper / aad mismatch (fail-closed)."""
    key = _load_key()
    try:
        blob = base64.b64decode(blob_b64)
    except (ValueError, TypeError) as exc:
        raise TokenizationError("malformed vault ciphertext (base64)") from exc
    if len(blob) < _NONCE_BYTES + 16:
        raise TokenizationError("vault ciphertext too short")
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad).decode("utf-8")
    except InvalidTag as exc:
        raise TokenizationError(
            "token-vault authentication failed (wrong key, tampered, or wrong tenant)"
        ) from exc
