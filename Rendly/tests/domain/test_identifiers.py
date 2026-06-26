"""Identifier discipline: only the canonical dashed UUID is accepted.

Exercised through a real entity (Tenant). Mirrors Delta D-001's non-canonical-UUID
rejection: ``uuid.UUID()`` would accept several of these, but the wire
``format: uuid`` + pattern do not, so the domain must not either (parser
differential / divergent join string).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.tenant import Tenant

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)
_GOOD = "12121212-1212-4212-8212-121212121212"


def test_canonical_uuid_accepted():
    assert Tenant(tenant_id=_GOOD, created_at=_NOW).tenant_id == _GOOD


@pytest.mark.parametrize(
    "bad",
    [
        "not-a-uuid",
        "12121212121242128212121212121212",  # no dashes (uuid.UUID would accept)
        "{12121212-1212-4212-8212-121212121212}",  # braces
        "urn:uuid:12121212-1212-4212-8212-121212121212",  # urn form
        "12121212-1212-4212-8212-1212121212",  # too short
        "g2121212-1212-4212-8212-121212121212",  # non-hex char
    ],
)
def test_noncanonical_uuid_rejected(bad):
    with pytest.raises(ValidationError):
        Tenant(tenant_id=bad, created_at=_NOW)


def test_naive_datetime_rejected():
    # The wire is RFC 3339 UTC; a naive datetime is ambiguous and rejected.
    with pytest.raises(ValidationError):
        Tenant(tenant_id=_GOOD, created_at=datetime(2026, 6, 26, 12, 0, 0))  # noqa: DTZ001
