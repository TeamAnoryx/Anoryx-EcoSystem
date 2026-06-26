"""Shared fixtures + non-stubbed factories for the R-002 domain suite.

Factories build REAL domain objects (no mocks/stubs) so the invariant tests
exercise the actual construction paths. No secrets, no PII in fixtures (random
UUIDs + a placeholder display name only) — mirrors the ecosystem test idiom.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timezone

import pytest

from rendly.channel import Channel
from rendly.enums import ChannelType, PresenceStatus
from rendly.user import User

_FIXED_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


def new_uuid() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def now() -> datetime:
    return _FIXED_NOW


@pytest.fixture
def make_user() -> Callable[..., User]:
    """Factory: a valid User in the given tenant; override any field via kwargs."""

    def _make(*, tenant_id: str, **over: object) -> User:
        fields: dict[str, object] = {
            "user_id": new_uuid(),
            "tenant_id": tenant_id,
            "display_name": "Alex Rivera",
            "presence": PresenceStatus.ONLINE,
            "created_at": _FIXED_NOW,
        }
        fields.update(over)
        return User(**fields)

    return _make


@pytest.fixture
def make_channel() -> Callable[..., Channel]:
    """Factory: a valid manual Channel in the given tenant; override via kwargs."""

    def _make(*, tenant_id: str, **over: object) -> Channel:
        fields: dict[str, object] = {
            "channel_id": new_uuid(),
            "tenant_id": tenant_id,
            "name": "eng-platform",
            "type": ChannelType.PRIVATE,
            "created_by": new_uuid(),
            "created_at": _FIXED_NOW,
        }
        fields.update(over)
        return Channel(**fields)

    return _make
