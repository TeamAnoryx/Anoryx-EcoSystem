"""R-020: the localized event-discovery seam over event.py (discovery.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.discovery import (
    MAX_LISTINGS,
    MAX_SUGGESTIONS,
    MAX_TOPICS,
    bind_discovery_profile,
    bind_event_listing,
    discover_event,
    discover_events,
)
from rendly.enums import OrgRole
from rendly.event import bind_event
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


def _discovery(profile: Profile, *, home_locale: str = "us-sf", interests=()):
    return bind_discovery_profile(
        profile, home_locale=home_locale, interests=interests, opted_in_at=_NOW
    )


def _listing(host_profile: Profile, *, locale: str = "us-sf", topics=(), title="Hack Day"):
    event = bind_event(host_profile, title=title, created_at=_NOW)
    return bind_event_listing(event, locale=locale, topics=topics)


# --- EventListing / DiscoveryProfile construction ----------------------------------------


def test_bind_event_listing_derives_ids_from_event():
    host = _profile("11111111-1111-4111-8111-111111111111")
    event = bind_event(host, title="Q3 Hackathon", created_at=_NOW)
    listing = bind_event_listing(event, locale="us-sf", topics=("rust", "ai"))
    assert listing.event_id == event.event_id
    assert listing.tenant_id == event.tenant_id
    assert listing.locale == "us-sf"
    assert set(listing.topics) == {"rust", "ai"}


def test_bind_discovery_profile_derives_ids_from_profile():
    profile = _profile("11111111-1111-4111-8111-111111111111")
    discovery = bind_discovery_profile(
        profile, home_locale="us-sf", interests=("rust",), opted_in_at=_NOW
    )
    assert discovery.user_id == profile.user_id
    assert discovery.tenant_id == profile.tenant_id
    assert discovery.home_locale == "us-sf"


def test_event_listing_rejects_too_many_topics():
    host = _profile("11111111-1111-4111-8111-111111111111")
    event = bind_event(host, title="Q3 Hackathon", created_at=_NOW)
    with pytest.raises(ValidationError, match="topics"):
        bind_event_listing(event, locale="us-sf", topics=[f"t{i}" for i in range(MAX_TOPICS + 1)])


def test_event_listing_rejects_duplicate_topics():
    host = _profile("11111111-1111-4111-8111-111111111111")
    event = bind_event(host, title="Q3 Hackathon", created_at=_NOW)
    with pytest.raises(ValidationError, match="topics"):
        bind_event_listing(event, locale="us-sf", topics=["rust", "rust"])


def test_discovery_profile_rejects_too_many_interests():
    profile = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError, match="interests"):
        bind_discovery_profile(
            profile,
            home_locale="us-sf",
            interests=[f"t{i}" for i in range(MAX_TOPICS + 1)],
            opted_in_at=_NOW,
        )


def test_discovery_profile_rejects_naive_datetime():
    profile = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError, match="timezone-aware"):
        bind_discovery_profile(
            profile,
            home_locale="us-sf",
            interests=("rust",),
            opted_in_at=datetime(2026, 7, 9, 12, 0, 0),
        )


# --- discover_event: locale filter + topic overlap -----------------------------------------


def test_discover_event_matches_on_same_locale_and_shared_topic():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    host = _profile("22222222-2222-4222-8222-222222222222")
    subject_discovery = _discovery(subject, home_locale="us-sf", interests=("rust", "ai"))
    listing = _listing(host, locale="us-sf", topics=("rust", "web3"))

    match = discover_event(subject, subject_discovery, listing)

    assert match is not None
    assert match.subject_user_id == subject.user_id
    assert match.event_id == listing.event_id
    assert match.locale == "us-sf"
    assert match.shared_topics == ("rust",)
    assert match.score == 1


def test_discover_event_none_when_locale_differs_even_with_shared_topics():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    host = _profile("22222222-2222-4222-8222-222222222222")
    subject_discovery = _discovery(subject, home_locale="us-sf", interests=("rust",))
    listing = _listing(host, locale="uk-london", topics=("rust",))

    assert discover_event(subject, subject_discovery, listing) is None


def test_discover_event_none_when_same_locale_but_no_shared_topics():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    host = _profile("22222222-2222-4222-8222-222222222222")
    subject_discovery = _discovery(subject, home_locale="us-sf", interests=("rust",))
    listing = _listing(host, locale="us-sf", topics=("web3",))

    assert discover_event(subject, subject_discovery, listing) is None


def test_discover_event_allows_cross_tenant_listing():
    # Deliberate divergence from culture.suggest_connection (R-012), mirroring
    # intent.suggest_match / peer.suggest_peer.
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    host = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    subject_discovery = _discovery(subject, home_locale="us-sf", interests=("rust",))
    listing = _listing(host, locale="us-sf", topics=("rust",))

    match = discover_event(subject, subject_discovery, listing)

    assert match is not None
    assert match.subject_tenant_id == _TENANT
    assert match.event_tenant_id == _OTHER_TENANT


def test_discover_event_rejects_mismatched_discovery_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    host = _profile("33333333-3333-4333-8333-333333333333")
    listing = _listing(host, locale="us-sf", topics=("rust",))

    with pytest.raises(ValueError, match="subject"):
        discover_event(subject, _discovery(other, interests=("rust",)), listing)


# --- discover_events: ranking ---------------------------------------------------------------


def test_discover_events_orders_by_score_desc_then_event_id_asc():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_discovery = _discovery(subject, home_locale="us-sf", interests=("rust", "ai", "web3"))
    host = _profile("22222222-2222-4222-8222-222222222222")

    strong = _listing(host, locale="us-sf", topics=("rust", "ai"), title="Strong")
    weak = _listing(host, locale="us-sf", topics=("rust",), title="Weak")
    off_locale = _listing(host, locale="uk-london", topics=("rust", "ai", "web3"), title="Remote")

    ranked = discover_events(subject, subject_discovery, [weak, strong, off_locale])

    assert [m.event_id for m in ranked] == [strong.event_id, weak.event_id]
    assert [m.score for m in ranked] == [2, 1]


def test_discover_events_filters_out_none_results():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_discovery = _discovery(subject, home_locale="us-sf", interests=("rust",))
    host = _profile("22222222-2222-4222-8222-222222222222")

    no_overlap = _listing(host, locale="us-sf", topics=("web3",))
    off_locale = _listing(host, locale="uk-london", topics=("rust",))

    assert discover_events(subject, subject_discovery, [no_overlap, off_locale]) == []


def test_discover_events_respects_limit_and_clamps_to_max():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_discovery = _discovery(subject, home_locale="us-sf", interests=("rust",))
    host = _profile("22222222-2222-4222-8222-222222222222")
    listings = [
        _listing(host, locale="us-sf", topics=("rust",), title=f"Event {i}") for i in range(3)
    ]

    assert len(discover_events(subject, subject_discovery, listings, limit=2)) == 2
    assert len(
        discover_events(subject, subject_discovery, listings, limit=MAX_SUGGESTIONS + 1000)
    ) <= len(listings)


def test_discover_events_rejects_oversized_listing_pool():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_discovery = _discovery(subject, home_locale="us-sf", interests=("rust",))
    host = _profile("22222222-2222-4222-8222-222222222222")
    listing = _listing(host, locale="us-sf", topics=("rust",))

    with pytest.raises(ValueError, match="listings"):
        discover_events(subject, subject_discovery, [listing] * (MAX_LISTINGS + 1))


def test_discover_events_includes_cross_tenant_listings():
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    subject_discovery = _discovery(subject, home_locale="us-sf", interests=("rust",))
    host = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    listing = _listing(host, locale="us-sf", topics=("rust",))

    ranked = discover_events(subject, subject_discovery, [listing])
    assert len(ranked) == 1
    assert ranked[0].event_tenant_id == _OTHER_TENANT
