"""Exceptions for provider key vaulting (F-027)."""

from __future__ import annotations


class KeyVaultError(Exception):
    """Base class for all provider-key-vaulting errors."""


class KeyFetchError(KeyVaultError):
    """Fetching credentials from the configured backend failed.

    Fail-closed: callers MUST treat this as "no credentials available" and
    NOT fall back to a stale or empty key (CLAUDE.md non-negotiable #5).
    """


class KeyNotConfigured(KeyVaultError):
    """No credentials are configured for this provider on this backend."""
