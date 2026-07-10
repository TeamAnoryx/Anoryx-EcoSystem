"""Air-gapped deployment exceptions (F-036, ADR-0041).

All fail-closed: a license/bundle/mirror problem raises rather than degrading to
a permissive default (CLAUDE.md #5).
"""

from __future__ import annotations


class AirgapError(Exception):
    """Base class for all air-gap deployment errors."""


class LicenseError(AirgapError):
    """A license is unreadable, malformed, expired, or fails signature verification."""


class LicenseKeyError(AirgapError):
    """The license verifying key is unset/unreadable/invalid (fail-closed)."""


class BundleError(AirgapError):
    """An offline install bundle failed integrity verification."""
