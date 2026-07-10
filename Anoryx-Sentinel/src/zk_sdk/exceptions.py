"""Exceptions for the F-032 zero-knowledge storage SDK."""

from __future__ import annotations


class ZkSdkError(Exception):
    """Base class for all zk_sdk errors."""


class InvalidKeyError(ZkSdkError):
    """A key is the wrong length or otherwise malformed."""


class DecryptionError(ZkSdkError):
    """Decryption failed — wrong key, or the ciphertext/nonce was tampered with.

    Fail-closed: never returns a guessed plaintext (the underlying AES-GCM tag
    check failed, which is exactly the tamper-evidence we want).
    """
