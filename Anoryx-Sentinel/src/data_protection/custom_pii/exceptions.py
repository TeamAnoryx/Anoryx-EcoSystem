"""Exceptions for the F-028 custom PII engine."""

from __future__ import annotations


class CustomPiiError(Exception):
    """Base class for all custom-PII errors."""


class InvalidPatternName(CustomPiiError):
    """The entity label failed validation."""


class InvalidPattern(CustomPiiError):
    """The regex failed validation (won't compile, too long, or ReDoS-risky)."""


class PatternLimitExceeded(CustomPiiError):
    """The tenant already has the maximum allowed number of active patterns."""
