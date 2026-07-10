"""Exceptions for the F-033 tokenization module."""

from __future__ import annotations


class TokenizationError(Exception):
    """Base class for tokenization errors."""


class TokenVaultKeyError(TokenizationError):
    """SENTINEL_TOKEN_VAULT_KEY is unset or not a valid base64 32-byte key.

    Fail-closed: tokenize/detokenize refuse rather than store or return
    plaintext without encryption.
    """


class UnsupportedFormatError(TokenizationError):
    """The value does not match the requested token format."""


class TokenNotFoundError(TokenizationError):
    """No vault row exists for the given token (for this tenant)."""
