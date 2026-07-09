"""R-014: the encrypted-live-streaming key-epoch/derivation/rotation seam (stream_crypto.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rendly.enums import OrgRole
from rendly.event import bind_event, schedule_session
from rendly.profile import Profile
from rendly.stream_crypto import (
    MAX_STREAM_PARTICIPANTS,
    StreamKeyEpoch,
    derive_participant_key,
    derive_roster_keys,
    mint_key_epoch,
    rotate_key_epoch,
)

_NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_HOST = "11111111-1111-4111-8111-111111111111"


def _host_profile() -> Profile:
    return Profile(user_id=_HOST, tenant_id=_TENANT, org_role=OrgRole.ADMIN, team="events")


def _session():
    event = bind_event(_host_profile(), title="Investor Update", created_at=_NOW)
    return schedule_session(
        event,
        (),
        title="Q3 Investor Update",
        starts_at=_NOW,
        ends_at=_NOW + timedelta(minutes=30),
    )


# --- MAX_STREAM_PARTICIPANTS stays reconciled with the R-013 session capacity bound -------


def test_max_stream_participants_matches_session_capacity():
    from rendly.event import MAX_SESSION_CAPACITY

    assert MAX_STREAM_PARTICIPANTS == MAX_SESSION_CAPACITY


# --- mint_key_epoch ------------------------------------------------------------------------


def test_mint_key_epoch_derives_ids_from_session():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    assert epoch.session_id == session.session_id
    assert epoch.tenant_id == session.tenant_id
    assert epoch.epoch == 0
    assert epoch.created_at == _NOW


def test_mint_key_epoch_master_key_is_32_random_bytes():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    assert isinstance(epoch.master_key, bytes)
    assert len(epoch.master_key) == 32


def test_mint_key_epoch_is_fresh_randomness_each_call():
    session = _session()
    first = mint_key_epoch(session, now=_NOW)
    second = mint_key_epoch(session, now=_NOW)
    assert first.master_key != second.master_key


def test_mint_key_epoch_rejects_naive_datetime():
    session = _session()
    with pytest.raises(ValueError, match="timezone-aware"):
        mint_key_epoch(session, now=datetime(2026, 7, 8, 12, 0, 0))


def test_master_key_excluded_from_repr():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    assert "master_key" not in repr(epoch)


def test_stream_key_epoch_is_frozen():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    with pytest.raises(AttributeError):
        epoch.epoch = 5  # type: ignore[misc]


# --- rotate_key_epoch ------------------------------------------------------------------------


def test_rotate_key_epoch_increments_generation_and_keeps_session_identity():
    session = _session()
    first = mint_key_epoch(session, now=_NOW)
    later = _NOW + timedelta(minutes=5)
    second = rotate_key_epoch(first, now=later)
    assert second.session_id == first.session_id
    assert second.tenant_id == first.tenant_id
    assert second.epoch == first.epoch + 1
    assert second.created_at == later


def test_rotate_key_epoch_is_forward_secret_not_derived_from_previous():
    session = _session()
    first = mint_key_epoch(session, now=_NOW)
    second = rotate_key_epoch(first, now=_NOW + timedelta(minutes=5))
    assert second.master_key != first.master_key


def test_rotate_key_epoch_rejects_non_monotonic_time():
    session = _session()
    first = mint_key_epoch(session, now=_NOW)
    with pytest.raises(ValueError, match="strictly follow"):
        rotate_key_epoch(first, now=_NOW)
    with pytest.raises(ValueError, match="strictly follow"):
        rotate_key_epoch(first, now=_NOW - timedelta(minutes=1))


def test_rotate_key_epoch_rejects_naive_datetime():
    session = _session()
    first = mint_key_epoch(session, now=_NOW)
    with pytest.raises(ValueError, match="timezone-aware"):
        rotate_key_epoch(first, now=datetime(2026, 7, 8, 12, 5, 0))


def test_rotate_key_epoch_chains_across_multiple_rotations():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    for i in range(1, 5):
        epoch = rotate_key_epoch(epoch, now=_NOW + timedelta(minutes=i))
        assert epoch.epoch == i


# --- derive_participant_key ------------------------------------------------------------------


def test_derive_participant_key_is_deterministic():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    first = derive_participant_key(epoch, "alice")
    second = derive_participant_key(epoch, "alice")
    assert first == second
    assert len(first) == 32


def test_derive_participant_key_differs_between_participants():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    assert derive_participant_key(epoch, "alice") != derive_participant_key(epoch, "bob")


def test_derive_participant_key_differs_across_epochs():
    session = _session()
    epoch0 = mint_key_epoch(session, now=_NOW)
    epoch1 = rotate_key_epoch(epoch0, now=_NOW + timedelta(minutes=5))
    assert derive_participant_key(epoch0, "alice") != derive_participant_key(epoch1, "alice")


def test_derive_participant_key_differs_across_sessions():
    session_a = _session()
    event_b = bind_event(_host_profile(), title="Different Event", created_at=_NOW)
    session_b = schedule_session(
        event_b,
        (),
        title="Different Session",
        starts_at=_NOW + timedelta(hours=1),
        ends_at=_NOW + timedelta(hours=1, minutes=30),
    )
    epoch_a = StreamKeyEpoch(
        session_id=session_a.session_id,
        tenant_id=session_a.tenant_id,
        epoch=0,
        created_at=_NOW,
        master_key=b"\x01" * 32,
    )
    epoch_b = StreamKeyEpoch(
        session_id=session_b.session_id,
        tenant_id=session_b.tenant_id,
        epoch=0,
        created_at=_NOW,
        master_key=b"\x01" * 32,
    )
    assert derive_participant_key(epoch_a, "alice") != derive_participant_key(epoch_b, "alice")


# --- derive_roster_keys ------------------------------------------------------------------------


def test_derive_roster_keys_returns_one_key_per_participant():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    keys = derive_roster_keys(epoch, ["alice", "bob", "carol"])
    assert set(keys) == {"alice", "bob", "carol"}
    assert keys["alice"] == derive_participant_key(epoch, "alice")


def test_derive_roster_keys_rejects_empty_roster():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    with pytest.raises(ValueError, match="must not be empty"):
        derive_roster_keys(epoch, [])


def test_derive_roster_keys_rejects_oversized_roster():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    roster = [f"user-{i}" for i in range(MAX_STREAM_PARTICIPANTS + 1)]
    with pytest.raises(ValueError, match="must not exceed"):
        derive_roster_keys(epoch, roster)


def test_derive_roster_keys_accepts_max_sized_roster():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    roster = [f"user-{i}" for i in range(MAX_STREAM_PARTICIPANTS)]
    keys = derive_roster_keys(epoch, roster)
    assert len(keys) == MAX_STREAM_PARTICIPANTS


def test_derive_roster_keys_rejects_duplicate_participant_ids():
    session = _session()
    epoch = mint_key_epoch(session, now=_NOW)
    with pytest.raises(ValueError, match="duplicate"):
        derive_roster_keys(epoch, ["alice", "bob", "alice"])
