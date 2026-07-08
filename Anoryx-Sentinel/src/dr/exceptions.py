"""F-024 disaster-recovery exceptions.

All DR errors derive from DrError. NEVER embed a connection URL (carries a
password), secrets, or raw row content in an exception message (CLAUDE.md
non-negotiable #4/#6) — only the error class / a redacted summary.
"""

from __future__ import annotations


class DrError(Exception):
    """Base class for all F-024 disaster-recovery errors."""


class BackupFailed(DrError):
    """pg_dump exited non-zero, or the resulting dump could not be stored."""


class RestoreFailed(DrError):
    """pg_restore exited non-zero."""


class ChainValidationFailed(DrError):
    """Post-restore hash-chain validation failed (fail-safe: restore is NOT
    considered usable — CLAUDE.md #5, never silently proceed on an integrity
    error)."""


class StorageDependencyMissing(DrError):
    """The optional S3 client is not installed.

    Raised with the exact `pip install` hint so a slim deploy without the
    [dr-s3] extra fails loud and actionable (mirrors the F-006 bedrock /
    F-015 bulk optional-extras discipline).
    """


class BackupNotFound(DrError):
    """The requested backup key does not exist in the configured sink."""
