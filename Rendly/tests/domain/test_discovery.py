"""R-020: the localized event-discovery seam (discovery.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rendly.discovery import (
    MAX_CANDIDATE_EVENTS,
    MAX_DISCOVERY_RESULTS,
    MAX_LOCALITIES,
    bind_event_locality,
    discover_events,
)
from rendly.enums import OrgRole
from rendly.event import MAX_SESSIONS_PER_EVENT, Event, bind_event, schedule_session
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_HOST_ID = "11111111-1111-4111-8111-111111111111"


def _host() -> Profile:
    return Profile(user_id=_HOST_ID, tenant_id=_TENANT, org_role=OrgRole.MEMBER)


def _event(title: str = "PyCon Meetup") -> Event:
    return bind_event(_host(), title=title, created_at=_NOW)


def _sessions(event: Event, *starts: datetime) -> list:
    sessions = []
    for start in starts:
        sessions.append(
            schedule_session(
                event,
                sessions,
                title="Talk",
                starts_at=start,
                ends_at=start + timedelta(hours=1),
            )
        )
    return sessions


# --- LocalizedEvent construction -----------------------------------------------------


def test_bind_event_locality_derives_ids_from_event():
    event = _event()
    tag = bind_event_locality(event, locality="san-francisco")
    assert tag.event_id == event.event_id
    assert tag.tenant_id == event.tenant_id
    assert tag.locality == "san-francisco"


def test_localized_event_is_frozen():
    event = _event()
    tag = bind_event_locality(event, locality="san-francisco")
    with pytest.raises(Exception):
        tag.locality = "remote"  # type: ignore[misc]


# --- discover_events: locality matching ------------------------------------------------


def test_discover_events_returns_only_exact_locality_matches():
    sf_event = _event("SF Hackathon")
    nyc_event = _event("NYC Hackathon")
    sf_tag = bind_event_locality(sf_event, locality="san-francisco")
    nyc_tag = bind_event_locality(nyc_event, locality="new-york")

    results = discover_events(
        ["san-francisco"],
        [(sf_event, sf_tag, []), (nyc_event, nyc_tag, [])],
    )
    assert [r.event_id for r in results] == [sf_event.event_id]


def test_discover_events_locality_match_is_exact_not_fuzzy():
    # "SF" and "san-francisco" are different opaque labels -- no geocoding, no
    # fuzzy match (see module HONESTY BOUNDARY).
    event = _event()
    tag = bind_event_locality(event, locality="SF")
    results = discover_events(["san-francisco"], [(event, tag, [])])
    assert results == []


def test_discover_events_matches_any_of_multiple_subject_localities():
    event = _event()
    tag = bind_event_locality(event, locality="remote")
    results = discover_events(["san-francisco", "remote"], [(event, tag, [])])
    assert len(results) == 1


def test_discover_events_empty_subject_localities_matches_nothing():
    event = _event()
    tag = bind_event_locality(event, locality="remote")
    assert discover_events([], [(event, tag, [])]) == []


# --- discover_events: ordering ----------------------------------------------------------


def test_discover_events_orders_by_next_session_ascending_then_event_id():
    later_event = _event("Later")
    sooner_event = _event("Sooner")
    later_tag = bind_event_locality(later_event, locality="remote")
    sooner_tag = bind_event_locality(sooner_event, locality="remote")

    later_sessions = _sessions(later_event, _NOW + timedelta(days=5))
    sooner_sessions = _sessions(sooner_event, _NOW + timedelta(days=1))

    results = discover_events(
        ["remote"],
        [(later_event, later_tag, later_sessions), (sooner_event, sooner_tag, sooner_sessions)],
    )
    assert [r.event_id for r in results] == [sooner_event.event_id, later_event.event_id]


def test_discover_events_uses_earliest_of_multiple_sessions():
    event = _event()
    tag = bind_event_locality(event, locality="remote")
    sessions = _sessions(
        event, _NOW + timedelta(days=10), _NOW + timedelta(days=2), _NOW + timedelta(days=20)
    )
    results = discover_events(["remote"], [(event, tag, sessions)])
    assert results[0].next_session_starts_at == _NOW + timedelta(days=2)


def test_discover_events_events_with_no_sessions_sort_last():
    with_session = _event("Has session")
    without_session = _event("No session")
    with_tag = bind_event_locality(with_session, locality="remote")
    without_tag = bind_event_locality(without_session, locality="remote")
    sessions = _sessions(with_session, _NOW + timedelta(days=1))

    results = discover_events(
        ["remote"],
        [(without_session, without_tag, []), (with_session, with_tag, sessions)],
    )
    assert [r.event_id for r in results] == [with_session.event_id, without_session.event_id]
    assert results[1].next_session_starts_at is None


# --- discover_events: bounds + provenance ------------------------------------------------


def test_discover_events_respects_limit_and_clamps_to_max():
    event = _event()
    tag = bind_event_locality(event, locality="remote")
    candidates = [(event, tag, [])]
    assert len(discover_events(["remote"], candidates, limit=0)) == 0
    assert len(discover_events(["remote"], candidates, limit=MAX_DISCOVERY_RESULTS + 1000)) <= 1


def test_discover_events_negative_limit_clamps_to_zero():
    event = _event()
    tag = bind_event_locality(event, locality="remote")
    assert discover_events(["remote"], [(event, tag, [])], limit=-1) == []


def test_discover_events_does_not_deduplicate_repeated_candidates():
    # Mirrors intent.rank_matches/career.rank_trajectory_matches's own documented
    # non-dedup behavior -- a caller passing the same event twice gets it twice.
    event = _event()
    tag = bind_event_locality(event, locality="remote")
    results = discover_events(["remote"], [(event, tag, []), (event, tag, [])])
    assert [r.event_id for r in results] == [event.event_id, event.event_id]


def test_discover_events_rejects_oversized_locality_list():
    with pytest.raises(ValueError, match="subject_localities"):
        discover_events([f"loc-{i}" for i in range(MAX_LOCALITIES + 1)], [])


def test_discover_events_rejects_oversized_subject_locality_entry():
    with pytest.raises(ValueError, match="subject_localities"):
        discover_events(["x" * 65], [])


def test_discover_events_rejects_oversized_candidate_pool():
    event = _event()
    tag = bind_event_locality(event, locality="remote")
    with pytest.raises(ValueError, match="candidates"):
        discover_events(["remote"], [(event, tag, [])] * (MAX_CANDIDATE_EVENTS + 1))


def test_discover_events_rejects_oversized_session_list_for_one_candidate():
    event = _event()
    tag = bind_event_locality(event, locality="remote")
    one_session = schedule_session(
        event, [], title="Talk", starts_at=_NOW, ends_at=_NOW + timedelta(hours=1)
    )
    with pytest.raises(ValueError, match="sessions"):
        discover_events(["remote"], [(event, tag, [one_session] * (MAX_SESSIONS_PER_EVENT + 1))])


def test_discover_events_rejects_mismatched_event_locality_pair():
    event = _event()
    other_event = _event("Other")
    other_tag = bind_event_locality(other_event, locality="remote")
    with pytest.raises(ValueError, match="event/locality"):
        discover_events(["remote"], [(event, other_tag, [])])


def test_discover_events_rejects_session_belonging_to_a_different_event():
    event = _event()
    other_event = _event("Other")
    tag = bind_event_locality(event, locality="remote")
    foreign_session = schedule_session(
        other_event, [], title="Talk", starts_at=_NOW, ends_at=_NOW + timedelta(hours=1)
    )
    with pytest.raises(ValueError, match="sessions"):
        discover_events(["remote"], [(event, tag, [foreign_session])])


def test_discover_events_includes_cross_tenant_events():
    # B2C discovery (like R-016/R-017/R-018's own matching) does not gate tenancy.
    other_tenant_host = Profile(
        user_id="22222222-2222-4222-8222-222222222222",
        tenant_id="99999999-9999-4999-8999-999999999999",
        org_role=OrgRole.MEMBER,
    )
    event = bind_event(other_tenant_host, title="Cross-tenant meetup", created_at=_NOW)
    tag = bind_event_locality(event, locality="remote")
    results = discover_events(["remote"], [(event, tag, [])])
    assert len(results) == 1
    assert results[0].tenant_id == other_tenant_host.tenant_id
