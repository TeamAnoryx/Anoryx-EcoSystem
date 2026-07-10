"""R-020: the localized tech-event discovery seam (event_discovery.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rendly.enums import OrgRole
from rendly.event import Event, EventSession, bind_event
from rendly.event_discovery import (
    VIRTUAL_LOCALITY,
    EventListing,
    bind_event_listing,
    discover_events,
)
from rendly.intent import IntentProfile
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_HOST = "11111111-1111-4111-8111-111111111111"
_SUBJECT = "22222222-2222-4222-8222-222222222222"


def _host_profile() -> Profile:
    return Profile(user_id=_HOST, tenant_id=_TENANT, org_role=OrgRole.ADMIN, team="events")


def _event(title: str = "Q3 Hackathon") -> Event:
    return bind_event(_host_profile(), title=title, created_at=_NOW)


def _session(event: Event, *, start_offset_min: int, duration_min: int = 60) -> EventSession:
    start = _NOW + timedelta(minutes=start_offset_min)
    return EventSession(
        session_id=f"{abs(start_offset_min):08d}-0000-4000-8000-000000000000",
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        title="Day 1",
        starts_at=start,
        ends_at=start + timedelta(minutes=duration_min),
        capacity=8,
    )


def _listing(event: Event, *, locality: str, topics=()) -> EventListing:
    return bind_event_listing(event, locality=locality, topics=topics)


def _intent(seeking=()) -> IntentProfile:
    return IntentProfile(
        user_id=_SUBJECT,
        tenant_id=_TENANT,
        seeking=tuple(seeking),
        offering=(),
        opted_in_at=_NOW,
    )


# --- locality filter ----------------------------------------------------------------------


def test_discover_events_includes_matching_locality():
    event = _event()
    session = _session(event, start_offset_min=60)
    listing = _listing(event, locality="san-francisco")

    results = discover_events("san-francisco", [(event, session, listing)], now=_NOW)

    assert len(results) == 1
    assert results[0].session_id == session.session_id
    assert results[0].locality == "san-francisco"


def test_discover_events_excludes_mismatched_locality():
    event = _event()
    session = _session(event, start_offset_min=60)
    listing = _listing(event, locality="new-york")

    results = discover_events("san-francisco", [(event, session, listing)], now=_NOW)

    assert results == []


def test_discover_events_includes_virtual_locality_regardless_of_subject():
    event = _event()
    session = _session(event, start_offset_min=60)
    listing = _listing(event, locality=VIRTUAL_LOCALITY)

    results = discover_events("anywhere-at-all", [(event, session, listing)], now=_NOW)

    assert len(results) == 1


# --- time filter ---------------------------------------------------------------------------


def test_discover_events_excludes_sessions_that_already_started():
    event = _event()
    started = _session(event, start_offset_min=-30)
    listing = _listing(event, locality="san-francisco")

    results = discover_events("san-francisco", [(event, started, listing)], now=_NOW)

    assert results == []


def test_discover_events_excludes_sessions_starting_exactly_now():
    event = _event()
    session = EventSession(
        session_id="00000001-0000-4000-8000-000000000000",
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        title="Day 1",
        starts_at=_NOW,
        ends_at=_NOW + timedelta(minutes=30),
        capacity=8,
    )
    listing = _listing(event, locality="san-francisco")

    results = discover_events("san-francisco", [(event, session, listing)], now=_NOW)

    assert results == []


# --- topic ranking (the matching-core composition) -----------------------------------------


def test_discover_events_zero_topic_score_still_included():
    event = _event()
    session = _session(event, start_offset_min=60)
    listing = _listing(event, locality="san-francisco", topics=("rust",))

    results = discover_events(
        "san-francisco", [(event, session, listing)], now=_NOW, subject_intent=_intent()
    )

    assert len(results) == 1
    assert results[0].score == 0
    assert results[0].matched_topics == ()


def test_discover_events_ranks_by_topic_overlap_desc_then_soonest():
    event = _event()
    high_match = _session(event, start_offset_min=120)
    low_match = _session(event, start_offset_min=60)

    listings = {
        high_match.session_id: _listing(event, locality="san-francisco", topics=("rust", "wasm")),
        low_match.session_id: _listing(event, locality="san-francisco", topics=("rust",)),
    }

    results = discover_events(
        "san-francisco",
        [
            (event, high_match, listings[high_match.session_id]),
            (event, low_match, listings[low_match.session_id]),
        ],
        now=_NOW,
        subject_intent=_intent(seeking=("rust", "wasm")),
    )

    assert [r.session_id for r in results] == [high_match.session_id, low_match.session_id]
    assert [r.score for r in results] == [2, 1]


def test_discover_events_no_subject_intent_yields_zero_score_for_all():
    event = _event()
    session = _session(event, start_offset_min=60)
    listing = _listing(event, locality="san-francisco", topics=("rust",))

    results = discover_events("san-francisco", [(event, session, listing)], now=_NOW)

    assert results[0].score == 0
    assert results[0].matched_topics == ()


# --- bounds + determinism -------------------------------------------------------------------


def test_discover_events_respects_limit_and_clamps_to_max():
    event = _event()
    from rendly.event_discovery import MAX_SUGGESTIONS

    candidates = [
        (
            event,
            _session(event, start_offset_min=60 + i),
            _listing(event, locality="san-francisco"),
        )
        for i in range(3)
    ]

    assert len(discover_events("san-francisco", candidates, now=_NOW, limit=2)) == 2
    assert len(
        discover_events("san-francisco", candidates, now=_NOW, limit=MAX_SUGGESTIONS + 1000)
    ) <= len(candidates)


def test_discover_events_rejects_oversized_candidate_pool():
    event = _event()
    session = _session(event, start_offset_min=60)
    listing = _listing(event, locality="san-francisco")

    with pytest.raises(ValueError, match="candidates"):
        discover_events("san-francisco", [(event, session, listing)] * 501, now=_NOW)


# --- validation ------------------------------------------------------------------------------


def test_discover_events_rejects_listing_for_a_different_event():
    event = _event()
    other_event = _event(title="Other Con")
    session = _session(event, start_offset_min=60)
    mismatched_listing = _listing(other_event, locality="san-francisco")

    with pytest.raises(ValueError, match="event/listing"):
        discover_events("san-francisco", [(event, session, mismatched_listing)], now=_NOW)


def test_discover_events_rejects_session_for_a_different_event():
    event = _event()
    other_event = _event(title="Other Con")
    mismatched_session = _session(other_event, start_offset_min=60)
    listing = _listing(event, locality="san-francisco")

    with pytest.raises(ValueError, match="session does not belong"):
        discover_events("san-francisco", [(event, mismatched_session, listing)], now=_NOW)


# --- EventListing validation -----------------------------------------------------------------


def test_event_listing_rejects_duplicate_topics():
    event = _event()
    with pytest.raises(ValueError):
        bind_event_listing(event, locality="san-francisco", topics=("rust", "rust"))


def test_event_listing_rejects_oversized_topics():
    event = _event()
    with pytest.raises(ValueError, match="exceed"):
        bind_event_listing(
            event, locality="san-francisco", topics=tuple(f"t{i}" for i in range(17))
        )


def test_bind_event_listing_derives_identity_from_event():
    event = _event()
    listing = bind_event_listing(event, locality="san-francisco")
    assert listing.event_id == event.event_id
    assert listing.tenant_id == event.tenant_id
