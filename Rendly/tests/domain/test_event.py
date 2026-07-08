"""R-013: the single-host virtual-event agenda scheduling seam (event.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from rendly.enums import OrgRole
from rendly.event import (
    MAX_SESSION_CAPACITY,
    MAX_SESSIONS_PER_EVENT,
    MIN_SESSION_CAPACITY,
    Event,
    EventSession,
    agenda,
    bind_event,
    schedule_session,
)
from rendly.profile import Profile
from rendly.realtime.huddle import MAX_HUDDLE_PARTICIPANTS

_NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"
_HOST = "11111111-1111-4111-8111-111111111111"


def _host_profile(tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=_HOST, tenant_id=tenant_id, org_role=OrgRole.ADMIN, team="events")


def _event(tenant_id: str = _TENANT) -> Event:
    return bind_event(_host_profile(tenant_id), title="Q3 Hackathon", created_at=_NOW)


def _window(start_offset_min: int, duration_min: int = 30) -> tuple[datetime, datetime]:
    start = _NOW + timedelta(minutes=start_offset_min)
    return start, start + timedelta(minutes=duration_min)


# --- constants stay reconciled with the R-011 huddle cap (ADR-0013 Fork B) --------------


def test_max_session_capacity_matches_huddle_cap():
    assert MAX_SESSION_CAPACITY == MAX_HUDDLE_PARTICIPANTS


# --- Event construction ------------------------------------------------------------------


def test_bind_event_derives_ids_from_host_profile():
    host = _host_profile()
    event = bind_event(host, title="Q3 Hackathon", created_at=_NOW)
    assert event.host_id == host.user_id
    assert event.tenant_id == host.tenant_id
    assert event.title == "Q3 Hackathon"


def test_event_is_frozen():
    event = _event()
    with pytest.raises(ValidationError):
        event.title = "Renamed"  # type: ignore[misc]


def test_event_rejects_naive_created_at():
    host = _host_profile()
    with pytest.raises(ValidationError):
        Event(
            event_id="22222222-2222-4222-8222-222222222222",
            tenant_id=host.tenant_id,
            host_id=host.user_id,
            title="Q3 Hackathon",
            created_at=datetime(2026, 7, 8, 12, 0, 0),  # naive
        )


def test_event_rejects_extra_key():
    host = _host_profile()
    with pytest.raises(ValidationError):
        Event(
            event_id="22222222-2222-4222-8222-222222222222",
            tenant_id=host.tenant_id,
            host_id=host.user_id,
            title="Q3 Hackathon",
            created_at=_NOW,
            broadcast=True,
        )


# --- schedule_session: happy path + determinism -------------------------------------------


def test_schedule_session_mints_new_session_bound_to_event():
    event = _event()
    starts_at, ends_at = _window(0)
    session = schedule_session(
        event, (), title="Opening keynote", starts_at=starts_at, ends_at=ends_at
    )
    assert session.event_id == event.event_id
    assert session.tenant_id == event.tenant_id
    assert session.starts_at == starts_at
    assert session.ends_at == ends_at
    assert session.capacity == MAX_SESSION_CAPACITY


def test_schedule_session_accepts_back_to_back_non_overlapping_sessions():
    event = _event()
    first_start, first_end = _window(0, duration_min=30)
    first = schedule_session(event, (), title="Track A", starts_at=first_start, ends_at=first_end)
    second_start, second_end = _window(30, duration_min=30)  # starts exactly when first ends
    second = schedule_session(
        event, (first,), title="Track B", starts_at=second_start, ends_at=second_end
    )
    assert second.starts_at == first.ends_at


@pytest.mark.parametrize(
    ("offset", "duration"),
    [
        (0, 30),  # identical window
        (10, 10),  # fully nested inside the existing session
        (-10, 30),  # overlaps the start
        (20, 30),  # overlaps the end
    ],
    ids=["identical", "nested", "overlaps-start", "overlaps-end"],
)
def test_schedule_session_rejects_any_overlap_on_same_event(offset, duration):
    event = _event()
    existing = schedule_session(
        event, (), title="Track A", starts_at=_window(0)[0], ends_at=_window(0)[1]
    )
    new_start, new_end = _window(offset, duration)
    with pytest.raises(ValueError, match="overlaps"):
        schedule_session(event, (existing,), title="Track B", starts_at=new_start, ends_at=new_end)


def test_schedule_session_rejects_sessions_from_a_different_event():
    event = _event()
    other_event = bind_event(_host_profile(), title="Different Event", created_at=_NOW)
    foreign_session = schedule_session(
        other_event, (), title="Foreign", starts_at=_window(0)[0], ends_at=_window(0)[1]
    )
    with pytest.raises(ValueError, match="same event"):
        schedule_session(
            event,
            (foreign_session,),
            title="Track B",
            starts_at=_window(100)[0],
            ends_at=_window(100)[1],
        )


def test_schedule_session_enforces_max_sessions_per_event():
    event = _event()
    sessions: tuple[EventSession, ...] = ()
    for i in range(MAX_SESSIONS_PER_EVENT):
        start, end = _window(i * 30, duration_min=30)
        sessions = (
            *sessions,
            schedule_session(event, sessions, title=f"T{i}", starts_at=start, ends_at=end),
        )
    overflow_start, overflow_end = _window(MAX_SESSIONS_PER_EVENT * 30, duration_min=30)
    with pytest.raises(ValueError, match="must not exceed"):
        schedule_session(
            event, sessions, title="Overflow", starts_at=overflow_start, ends_at=overflow_end
        )


@pytest.mark.parametrize("capacity", [MIN_SESSION_CAPACITY - 1, MAX_SESSION_CAPACITY + 1, 0, -1])
def test_schedule_session_rejects_out_of_bounds_capacity(capacity):
    event = _event()
    starts_at, ends_at = _window(0)
    with pytest.raises(ValidationError):
        schedule_session(
            event, (), title="Track A", starts_at=starts_at, ends_at=ends_at, capacity=capacity
        )


def test_event_session_rejects_ends_before_starts():
    starts_at, _ = _window(0)
    with pytest.raises(ValidationError, match="ends_at must be strictly after starts_at"):
        EventSession(
            session_id="33333333-3333-4333-8333-333333333333",
            event_id="22222222-2222-4222-8222-222222222222",
            tenant_id=_TENANT,
            title="Backwards",
            starts_at=starts_at,
            ends_at=starts_at - timedelta(minutes=1),
            capacity=MAX_SESSION_CAPACITY,
        )


# --- agenda: deterministic ordering -------------------------------------------------------


def test_agenda_sorts_by_start_time():
    event = _event()
    later = schedule_session(
        event, (), title="Later", starts_at=_window(60)[0], ends_at=_window(60)[1]
    )
    earlier = schedule_session(
        event, (later,), title="Earlier", starts_at=_window(0)[0], ends_at=_window(0)[1]
    )
    ordered = agenda((later, earlier))
    assert ordered == [earlier, later]


def test_agenda_breaks_ties_on_session_id():
    event = _event()
    start, end = _window(0)
    a = EventSession(
        session_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        title="A",
        starts_at=start,
        ends_at=end,
        capacity=MAX_SESSION_CAPACITY,
    )
    b = EventSession(
        session_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        title="B",
        starts_at=start,
        ends_at=end,
        capacity=MAX_SESSION_CAPACITY,
    )
    assert agenda((b, a)) == [a, b]
    assert agenda((a, b)) == [a, b]
