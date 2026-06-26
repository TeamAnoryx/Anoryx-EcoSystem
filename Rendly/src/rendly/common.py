"""Shared field validators for the Rendly domain model.

Kept tiny and dependency-free so every entity module can reuse the same
timezone discipline without a circular import. The wire is RFC 3339 UTC
(``contracts/openapi.yaml`` / ``messages.schema.json`` ``iso_datetime``), so a
naive datetime is rejected at the domain boundary — never silently assumed UTC.
"""

from __future__ import annotations

from datetime import datetime


def require_aware_utc(value: datetime, field_name: str) -> datetime:
    """Require a timezone-aware datetime (the wire format is RFC 3339 UTC).

    A naive datetime (no tzinfo / no offset) is ambiguous and would serialize to
    a wire string without a zone, so it is rejected rather than coerced.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware (UTC)")
    return value
