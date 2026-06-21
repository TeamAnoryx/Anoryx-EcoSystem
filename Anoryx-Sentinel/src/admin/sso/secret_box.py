"""Symmetric encrypt-at-rest helper for IdP secrets (F-014 D3, ADR-0017 §4; R6).

DESIGN INTENT (honest — not an absolute claim):
  * IdP secret material (the OIDC client_secret and any SAML SP private key) is
    NEVER stored in plaintext. This module wraps `cryptography`'s AES-256-GCM
    (cryptography.hazmat.primitives.ciphers.aead.AESGCM) — a vetted AEAD
    construction. No crypto is hand-rolled (R3).
  * Blob layout is `nonce ‖ AESGCM.encrypt(...)`, i.e. a 12-byte random nonce
    prepended to the library's `ciphertext‖tag` output. A fresh nonce is drawn
    per encrypt via os.urandom(12) and never reused — GCM nonce reuse under one
    key is catastrophic, so each call generates its own.
  * The key is loaded ONCE from SENTINEL_IDP_SECRET_KEY (base64 of exactly 32
    bytes), cached, and FAIL-CLOSED (mirrors policy.crypto.load_verifying_key):
      - unset  -> the FIRST encrypt/decrypt raises IdpSecretKeyError, so an IdP
        config write REFUSES rather than silently storing plaintext. Module
        import never crashes on an unset key (so unrelated admin routes still
        import); the failure is deferred to the point of use.
      - set-but-invalid (not base64, or not exactly 32 decoded bytes) -> raises
        IdpSecretKeyError at LOAD time (a deployment misconfiguration, surfaced
        immediately on first use rather than producing wrong-length-key errors
        deep inside the cipher).
  * Decryption is out of every logging path. This module NEVER logs the key, the
    plaintext, or the ciphertext — there is no logger here by design. Callers
    MUST keep decrypted material out of logs/audit rows too (R6).
  * GCM authentication: tampering with the nonce or ciphertext makes
    AESGCM.decrypt raise cryptography.exceptions.InvalidTag, which this module
    surfaces unchanged (fail-closed; never returns a guessed plaintext).

Provisioning: SENTINEL_IDP_SECRET_KEY is Vault/KMS-injected at deploy
(CLAUDE.md non-negotiable #4) — never in code, config, logs, or tests. Tests
assemble an ephemeral key at runtime (base64(os.urandom(32))).
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_IDP_SECRET_KEY_ENV = "SENTINEL_IDP_SECRET_KEY"  # noqa: S105 — env var NAME, not a secret
_KEY_BYTES = 32  # AES-256
_NONCE_BYTES = 12  # GCM standard nonce length

__all__ = [
    "IdpSecretKeyError",
    "encrypt",
    "decrypt",
    "reset_key_cache_for_testing",
]


class IdpSecretKeyError(RuntimeError):
    """SENTINEL_IDP_SECRET_KEY is unset, or set but not a valid base64 32-byte key.

    Fail-closed: when this is raised on an encrypt path, the IdP config write
    refuses (never stores plaintext); when raised at load time it signals a
    deployment misconfiguration (R3).
    """


# --------------------------------------------------------------------------- #
# Load-once, fail-closed key loader (mirrors policy.crypto.load_verifying_key).
# --------------------------------------------------------------------------- #
_key: bytes | None = None
_key_loaded = False


def _load_key() -> bytes:
    """Load (once, cached) the 32-byte AES key from SENTINEL_IDP_SECRET_KEY.

    Raises IdpSecretKeyError when the env var is unset (so encrypt/decrypt
    refuse — config writes never silently store plaintext) or when it is set but
    is not base64 of exactly 32 bytes (deployment misconfig). The key bytes are
    never logged.
    """
    global _key, _key_loaded
    if _key_loaded:
        if _key is None:
            raise IdpSecretKeyError(
                f"{_IDP_SECRET_KEY_ENV} is not set; IdP secret encryption is "
                "unavailable (fail-closed — config writes refuse rather than "
                "store plaintext)."
            )
        return _key

    raw = os.environ.get(_IDP_SECRET_KEY_ENV, "").strip()
    if not raw:
        # Cache the unset state so the next call still fails-closed without a
        # re-read, and so reset_for_testing is required to pick up a later set.
        _key = None
        _key_loaded = True
        raise IdpSecretKeyError(
            f"{_IDP_SECRET_KEY_ENV} is not set; IdP secret encryption is "
            "unavailable (fail-closed — config writes refuse rather than "
            "store plaintext)."
        )

    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, TypeError) as exc:  # binascii.Error subclasses ValueError
        # Cache the bad-key state (loaded=True, key=None) so subsequent calls
        # fail-closed without a re-read — consistent with the unset-key path above
        # (F-014 code-review LOW). reset_key_cache_for_testing picks up a corrected
        # env. Never echo the raw value.
        _key = None
        _key_loaded = True
        raise IdpSecretKeyError(f"{_IDP_SECRET_KEY_ENV} is set but is not valid base64") from exc

    if len(decoded) != _KEY_BYTES:
        # Same cached bad-key state as the base64-failure branch (fail-closed).
        _key = None
        _key_loaded = True
        raise IdpSecretKeyError(
            f"{_IDP_SECRET_KEY_ENV} must decode to exactly {_KEY_BYTES} bytes "
            f"(AES-256); got {len(decoded)} bytes"
        )

    _key = decoded
    _key_loaded = True
    return _key


# --------------------------------------------------------------------------- #
# Encrypt / decrypt
# --------------------------------------------------------------------------- #
def encrypt(plaintext: str | bytes) -> bytes:
    """Encrypt *plaintext* to a `nonce ‖ ciphertext‖tag` blob (AES-256-GCM).

    A fresh 12-byte nonce is generated per call (os.urandom) and prepended to the
    AESGCM.encrypt output. str input is UTF-8 encoded. Raises IdpSecretKeyError
    when the key is unset/invalid (fail-closed — the caller must NOT store
    anything on failure).
    """
    key = _load_key()
    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(key).encrypt(nonce, data, None)
    return nonce + sealed


def decrypt(blob: bytes) -> bytes:
    """Decrypt a `nonce ‖ ciphertext‖tag` blob produced by encrypt().

    Raises IdpSecretKeyError when the key is unset/invalid, ValueError when the
    blob is too short to contain a nonce, and
    cryptography.exceptions.InvalidTag when authentication fails (tampered nonce
    or ciphertext) — never returns a guessed plaintext (fail-closed).
    """
    key = _load_key()
    if len(blob) <= _NONCE_BYTES:
        raise ValueError("ciphertext blob is too short to contain a GCM nonce")
    nonce, sealed = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, sealed, None)


def reset_key_cache_for_testing() -> None:
    """Reset the load-once cache so a test can point at a fresh key (or unset)."""
    global _key, _key_loaded
    _key = None
    _key_loaded = False
