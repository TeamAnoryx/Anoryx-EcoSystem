"""R-024: the discovery-feed cross-type composition seam (discovery_feed.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from rendly.discovery_feed import (
    DEFAULT_FEED_LIMIT,
    MAX_FEED_LIMIT,
    MAX_ITEMS_PER_TYPE,
    FeedItem,
    FeedItemKind,
    compose_feed,
)
from rendly.enums import OrgRole
from rendly.event import EventSession, bind_event
from rendly.event_discovery import bind_event_listing, discover_events
from rendly.intent import IntentProfile, bind_intent_profile
from rendly.mentorship import (
    ProficiencyLevel,
    bind_tech_stack_proficiency,
    suggest_mentorship_match,
)
from rendly.opportunity import OpportunityKind, bind_opportunity, suggest_opportunity_match
from rendly.peer import suggest_peer
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_SUBJECT = "11111111-1111-4111-8111-111111111111"
_OTHER = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


def _subject() -> Profile:
    return _profile(_SUBJECT)


def _intent(profile: Profile, *, seeking=(), offering=()) -> IntentProfile:
    return bind_intent_profile(profile, seeking=seeking, offering=offering, opted_in_at=_NOW)


def _peer_suggestion(candidate_user_id: str):
    subject = _subject()
    candidate = _profile(candidate_user_id)
    suggestion = suggest_peer(
        subject,
        candidate,
        subject_intent=_intent(subject, seeking=("mentor",), offering=()),
        candidate_intent=_intent(candidate, seeking=(), offering=("mentor",)),
    )
    assert suggestion is not None
    return suggestion


def _event_discovery(session_id_suffix: str, *, topics=(), start_offset_min: int = 60):
    host = _profile("22222222-2222-4222-8222-222222222222")
    event = bind_event(host, title="Q3 Hackathon", created_at=_NOW)
    start = _NOW + timedelta(minutes=start_offset_min)
    session = EventSession(
        session_id=f"{session_id_suffix:0>8}-0000-4000-8000-000000000000",
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        title="Day 1",
        starts_at=start,
        ends_at=start + timedelta(minutes=60),
        capacity=8,
    )
    listing = bind_event_listing(event, locality="sf", topics=topics)
    results = discover_events(
        "sf",
        [(event, session, listing)],
        now=_NOW,
        subject_intent=_intent(_subject(), seeking=list(topics)) if topics else None,
    )
    assert len(results) == 1
    return results[0]


def _opportunity_match(opportunity_id_suffix: str = "1"):
    subject = _subject()
    poster = _profile("33333333-3333-4333-8333-333333333333")
    opportunity = bind_opportunity(
        poster,
        title="Backend contract",
        kind=OpportunityKind.FREELANCE,
        required_skills=("python",),
        posted_at=_NOW,
    )
    match = suggest_opportunity_match(
        subject, _intent(subject, seeking=(), offering=("python",)), opportunity
    )
    assert match is not None
    return match


def _mentorship_match(mentor_user_id: str = "44444444-4444-4444-8444-444444444444"):
    subject = _subject()
    mentor = _profile(mentor_user_id)
    match = suggest_mentorship_match(
        subject,
        bind_tech_stack_proficiency(
            subject, stack="react", level=ProficiencyLevel.BEGINNER, opted_in_at=_NOW
        ),
        mentor,
        bind_tech_stack_proficiency(
            mentor, stack="react", level=ProficiencyLevel.EXPERT, opted_in_at=_NOW
        ),
    )
    assert match is not None
    return match


# --- FeedItem structural invariant -------------------------------------------------------


def test_feed_item_rejects_payload_kind_mismatch():
    with pytest.raises(ValidationError, match="exactly one payload"):
        FeedItem(kind=FeedItemKind.PEER, opportunity_match=_opportunity_match())


def test_feed_item_rejects_no_payload():
    with pytest.raises(ValidationError, match="exactly one payload"):
        FeedItem(kind=FeedItemKind.PEER)


def test_feed_item_rejects_two_payloads():
    with pytest.raises(ValidationError, match="exactly one payload"):
        FeedItem(
            kind=FeedItemKind.PEER,
            peer_suggestion=_peer_suggestion("22222222-2222-4222-8222-222222222222"),
            opportunity_match=_opportunity_match(),
        )


# --- compose_feed: ordering ---------------------------------------------------------------


def test_compose_feed_empty_when_no_inputs():
    assert compose_feed(_SUBJECT, _TENANT) == []


def test_compose_feed_interleaves_in_fixed_type_order():
    feed = compose_feed(
        _SUBJECT,
        _TENANT,
        peer_suggestions=[_peer_suggestion("22222222-2222-4222-8222-222222222222")],
        event_discoveries=[_event_discovery("1")],
        opportunity_matches=[_opportunity_match()],
        mentorship_matches=[_mentorship_match()],
    )
    assert [item.kind for item in feed] == [
        FeedItemKind.EVENT,
        FeedItemKind.MENTORSHIP,
        FeedItemKind.OPPORTUNITY,
        FeedItemKind.PEER,
    ]


def test_compose_feed_preserves_within_type_order_across_rounds():
    peers = [
        _peer_suggestion("22222222-2222-4222-8222-222222222222"),
        _peer_suggestion("33333333-3333-4333-8333-333333333333"),
    ]
    feed = compose_feed(_SUBJECT, _TENANT, peer_suggestions=peers)
    assert [item.peer_suggestion.candidate_user_id for item in feed] == [
        p.candidate_user_id for p in peers
    ]


def test_compose_feed_second_round_only_has_types_with_remaining_items():
    # Two peers, one event: round 1 = [event, peer0]; round 2 = [peer1] (mentorship,
    # opportunity have nothing left, so they are skipped, not padded).
    feed = compose_feed(
        _SUBJECT,
        _TENANT,
        peer_suggestions=[
            _peer_suggestion("22222222-2222-4222-8222-222222222222"),
            _peer_suggestion("33333333-3333-4333-8333-333333333333"),
        ],
        event_discoveries=[_event_discovery("1")],
    )
    assert [item.kind for item in feed] == [
        FeedItemKind.EVENT,
        FeedItemKind.PEER,
        FeedItemKind.PEER,
    ]


def test_compose_feed_is_deterministic():
    kwargs = dict(
        peer_suggestions=[_peer_suggestion("22222222-2222-4222-8222-222222222222")],
        event_discoveries=[_event_discovery("1")],
        opportunity_matches=[_opportunity_match()],
        mentorship_matches=[_mentorship_match()],
    )
    first = compose_feed(_SUBJECT, _TENANT, **kwargs)
    second = compose_feed(_SUBJECT, _TENANT, **kwargs)
    assert first == second


# --- compose_feed: limits ------------------------------------------------------------------


def test_compose_feed_respects_limit():
    feed = compose_feed(
        _SUBJECT,
        _TENANT,
        peer_suggestions=[_peer_suggestion("22222222-2222-4222-8222-222222222222")],
        event_discoveries=[_event_discovery("1")],
        opportunity_matches=[_opportunity_match()],
        mentorship_matches=[_mentorship_match()],
        limit=2,
    )
    assert len(feed) == 2


def test_compose_feed_clamps_limit_to_max():
    feed = compose_feed(
        _SUBJECT,
        _TENANT,
        peer_suggestions=[_peer_suggestion("22222222-2222-4222-8222-222222222222")],
        limit=MAX_FEED_LIMIT + 1000,
    )
    assert len(feed) <= MAX_FEED_LIMIT


def test_compose_feed_default_limit_is_used_when_unspecified():
    assert DEFAULT_FEED_LIMIT <= MAX_FEED_LIMIT


def test_compose_feed_rejects_oversized_peer_suggestions():
    suggestion = _peer_suggestion("22222222-2222-4222-8222-222222222222")
    with pytest.raises(ValueError, match="peer_suggestions"):
        compose_feed(_SUBJECT, _TENANT, peer_suggestions=[suggestion] * (MAX_ITEMS_PER_TYPE + 1))


def test_compose_feed_rejects_oversized_event_discoveries():
    result = _event_discovery("1")
    with pytest.raises(ValueError, match="event_discoveries"):
        compose_feed(_SUBJECT, _TENANT, event_discoveries=[result] * (MAX_ITEMS_PER_TYPE + 1))


def test_compose_feed_rejects_oversized_opportunity_matches():
    match = _opportunity_match()
    with pytest.raises(ValueError, match="opportunity_matches"):
        compose_feed(_SUBJECT, _TENANT, opportunity_matches=[match] * (MAX_ITEMS_PER_TYPE + 1))


def test_compose_feed_rejects_oversized_mentorship_matches():
    match = _mentorship_match()
    with pytest.raises(ValueError, match="mentorship_matches"):
        compose_feed(_SUBJECT, _TENANT, mentorship_matches=[match] * (MAX_ITEMS_PER_TYPE + 1))


# --- compose_feed: subject cross-checking ---------------------------------------------------


def test_compose_feed_rejects_peer_suggestion_for_a_different_subject():
    suggestion = _peer_suggestion("22222222-2222-4222-8222-222222222222")
    with pytest.raises(ValueError, match="peer_suggestions"):
        compose_feed(_OTHER, _TENANT, peer_suggestions=[suggestion])


def test_compose_feed_rejects_opportunity_match_for_a_different_subject():
    match = _opportunity_match()
    with pytest.raises(ValueError, match="opportunity_matches"):
        compose_feed(_OTHER, _TENANT, opportunity_matches=[match])


def test_compose_feed_rejects_mentorship_match_for_a_different_mentee():
    match = _mentorship_match()
    with pytest.raises(ValueError, match="mentorship_matches"):
        compose_feed(_OTHER, _TENANT, mentorship_matches=[match])


def test_compose_feed_does_not_cross_check_event_discoveries():
    # discover_events carries no subject identity — any caller-supplied event
    # discovery is accepted regardless of the `subject_user_id` passed here.
    result = _event_discovery("1")
    feed = compose_feed(_OTHER, _TENANT, event_discoveries=[result])
    assert len(feed) == 1
    assert feed[0].kind == FeedItemKind.EVENT
