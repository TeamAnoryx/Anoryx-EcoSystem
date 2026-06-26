"""Channel mirrors the LOCKED wire shape; the Delta-team seam stays self-consistent."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.channel import Channel
from rendly.enums import ChannelSource, ChannelType

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)
_T = "12121212-1212-4212-8212-121212121212"
_C = "14141414-1414-4414-8414-141414141414"
_U = "13131313-1313-4313-8313-131313131313"


def _channel(**over: object) -> Channel:
    base: dict[str, object] = {
        "channel_id": _C,
        "tenant_id": _T,
        "name": "eng",
        "type": ChannelType.PRIVATE,
        "created_by": _U,
        "created_at": _NOW,
    }
    base.update(over)
    return Channel(**base)


def test_defaults_manual_unarchived_no_ref():
    # A normally-constructed channel is the manual seam state (honesty boundary).
    c = _channel()
    assert c.source is ChannelSource.MANUAL
    assert c.external_ref is None
    assert c.archived is False


def test_delta_team_with_external_ref_ok():
    # Reserved seam shape: a delta_team channel names what it maps to.
    c = _channel(source=ChannelSource.DELTA_TEAM, external_ref="delta-team-42")
    assert c.source is ChannelSource.DELTA_TEAM
    assert c.external_ref == "delta-team-42"


def test_manual_with_external_ref_rejected():
    # A manual channel can never carry a mapping pointer.
    with pytest.raises(ValidationError, match="manual channel must not carry"):
        _channel(source=ChannelSource.MANUAL, external_ref="x")


def test_delta_team_without_external_ref_rejected():
    with pytest.raises(ValidationError, match="delta_team channel requires"):
        _channel(source=ChannelSource.DELTA_TEAM, external_ref=None)


def test_rejects_bad_type():
    # 'role_mapped' was the dispatch's tentative value; the LOCKED enum is {public,private,dm}.
    with pytest.raises(ValidationError):
        _channel(type="role_mapped")


def test_rejects_empty_name():
    with pytest.raises(ValidationError):
        _channel(name="")


def test_rejects_extra_key():
    # 'delta_team_id' is the dispatch's superseded field name — not a field here.
    with pytest.raises(ValidationError):
        _channel(delta_team_id="x")


def test_external_ref_charset_rejected():
    # The reserved seam pointer is charset-bounded (log-injection defense): control
    # chars / CRLF / path-traversal / URL payloads are rejected before any R-006
    # consumer dereferences it.
    with pytest.raises(ValidationError):
        _channel(source=ChannelSource.DELTA_TEAM, external_ref="x\r\ninjected: pwn /../")
