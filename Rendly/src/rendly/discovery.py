"""Discovery — a deterministic, opt-in, exact-locale event-discovery seam over the
Event (R-013) scheduling seam (R-020 = FORK A1/B1/C1).

HONESTY BOUNDARY (verbatim, non-removable): "Localized tech-event / hackathon /
startup discovery" in the roadmap's task name is NOT implemented here as either
geolocation or a recommendation model. What ships is a DETERMINISTIC, exact-string
locale filter combined with a tag-overlap ranker — no geocoding, no proximity/
distance computation, no model, no learned ranking. This is a deliberate scope-down
of R-020 (~10-16h, 🏦 POST-INVESTMENT, fifth task of Rendly's B2C professional-
networking tier) to a minimal discovery CORE, in the same spirit as R-012's,
R-016's, R-017's, and R-018's own scoped deliveries (see ADR-0012 §Decision,
ADR-0016 §Decision, ADR-0017 §Decision, ADR-0018 §Decision) — this module
reproduces their discipline rather than inventing a new one. See ADR-0020 for the
full fork-by-fork rationale.

"Localized" ships as an OPAQUE, caller-supplied locale tag (e.g. ``"us-sf"``,
``"remote"``) compared for EXACT equality — never a real-world coordinate, radius,
or haversine distance. Two listings a caller considers "nearby" but tags with
different locale strings will NOT match; this module trusts its caller's tagging
the same way every other seam in this codebase trusts its caller's tag input
(``culture.py``'s ``Interest``, ``intent.py``'s ``IntentTag``).

NOT BUILT HERE (mirrors ADR-0016's/ADR-0017's/ADR-0018's own lists): real B2C
consumer identity/onboarding (R-023, still unshipped) — this module operates over
the EXISTING enterprise ``Profile`` domain (R-002) as a placeholder actor model,
exactly as R-012/R-016/R-017/R-018 did. No geocoding/mapping integration, no
persistence, no REST/wire surface, no ML.

The discoverable ITEM is the existing R-013 ``Event`` (``event.py``) — this module
does not invent a new "event" concept, it adds discovery METADATA
(``EventListing``: a locale tag + topic tags) bound to a real ``Event``, mirroring
how ``EventSession`` is bound to an ``Event`` via ``event_id``/``tenant_id`` rather
than being a wholly separate entity.

PRIVACY-CONTROLLED, by construction, not by policy (mirrors ``culture.py``/
``intent.py``/``career.py``): a user who has never called
:func:`bind_discovery_profile` has no ``DiscoveryProfile`` record and structurally
cannot appear as a discovery subject — every function in this module requires an
explicit opt-in object as an argument.

DELIBERATE DIVERGENCE FROM ``culture.py`` (R-012), consistent WITH ``intent.py``
(R-016) / ``career.py`` (R-017) / ``peer.py`` (R-018): event discovery does NOT
reject cross-tenant pairs. A hackathon/startup event's whole discovery value is
CROSS-company (a subject at one tenant discovering an event hosted by another
tenant is the point, not an edge case) — so :func:`discover_event` /
:func:`discover_events` do not inspect the listing's ``tenant_id`` relative to the
subject's.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from .common import require_aware_utc
from .event import Event
from .identifiers import EventId, TenantId, UserId
from .profile import Profile

# An opaque locale tag: short, non-empty, bounded (mirrors `culture.py`'s `Interest`
# discipline). Exact-match only — see module docstring "Localized" section. Examples:
# "us-sf", "uk-london", "remote". Not validated against any real geo/IANA reference.
Locale = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# A topic tag: short, non-empty, bounded (mirrors `intent.py`'s `IntentTag`).
Topic = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# Bounded field discipline (mirrors `culture.py`'s MAX_INTERESTS, `intent.py`'s
# MAX_TAGS): both a listing's topic tags and a subject's interest tags are capped so
# neither storage nor the O(n*m) pairwise scorer below is exposed to an unbounded
# input.
MAX_TOPICS = 16

# Bounds the candidate listing pool + the result set of a single ranking call
# (mirrors `intent.py`'s/`peer.py`'s MAX_CANDIDATES/MAX_SUGGESTIONS at the same
# magnitudes — a DoS/cost guard on the pairwise scorer, not a product decision about
# "how many events are useful").
MAX_LISTINGS = 500
MAX_SUGGESTIONS = 50
DEFAULT_MATCH_LIMIT = 10


def _bounded_and_deduped_tags(value: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if len(value) > MAX_TOPICS:
        raise ValueError(f"{label} must not exceed {MAX_TOPICS} tags")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must not contain duplicates")
    return value


class EventListing(BaseModel):
    """Discovery metadata bound to a real ``Event`` (R-013). Immutable.

    Direct ``EventListing(...)`` construction with a hand-supplied ``event_id`` is a
    lower-level primitive (mirrors ``EventSession``'s same reservation, ADR-0013)
    that is NOT validated against a real ``Event``; :func:`bind_event_listing` is the
    canonical, validated path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: EventId
    tenant_id: TenantId
    locale: Locale
    topics: tuple[Topic, ...]

    @field_validator("topics")
    @classmethod
    def _bounded_topics(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_and_deduped_tags(value, label="topics")


def bind_event_listing(event: Event, *, locale: str, topics: Sequence[str]) -> EventListing:
    """Build an ``EventListing`` bound to a real ``Event`` (the canonical path).

    ``event_id``/``tenant_id`` are read FROM the event, mirroring
    :func:`rendly.event.bind_event` and :func:`rendly.intent.bind_intent_profile` —
    a listing's identity is derived from a validated event, never hand-supplied.
    """
    return EventListing(
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        locale=locale,
        topics=tuple(topics),
    )


class DiscoveryProfile(BaseModel):
    """A user's explicit, revocable opt-in into localized event discovery.

    Immutable. Absence of a ``DiscoveryProfile`` for a user is the ONLY "opted out"
    state this module models — there is no separate boolean to forget to check.
    ``home_locale`` is a single opaque tag (see module docstring); a user who wants
    to discover events in multiple locales opts in multiple times (one profile per
    locale), the same bounded-list-avoidance choice ``culture.py``'s single-tenant
    scope makes rather than admitting an unbounded locale list.

    Direct ``DiscoveryProfile(...)`` construction with hand-supplied ids is a
    lower-level primitive that is NOT validated against any real ``Profile``
    (mirrors ``culture.CultureOptIn``'s same reservation); it exists for
    rehydrating an already-validated record. All application code that mints a NEW
    discovery profile MUST use :func:`bind_discovery_profile`. ``discover_event`` /
    ``discover_events`` still cross-check the profile/opt-in pair (``_require_bound``),
    so a mismatched pair fails at use time either way.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    home_locale: Locale
    interests: tuple[Topic, ...]
    opted_in_at: datetime

    @field_validator("opted_in_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "opted_in_at")

    @field_validator("interests")
    @classmethod
    def _bounded_interests(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_and_deduped_tags(value, label="interests")


def bind_discovery_profile(
    user_profile: Profile,
    *,
    home_locale: str,
    interests: Sequence[str],
    opted_in_at: datetime,
) -> DiscoveryProfile:
    """Build a ``DiscoveryProfile`` bound to a real ``Profile`` (the canonical path).

    ``user_id``/``tenant_id`` are read FROM the profile, mirroring
    :func:`rendly.culture.bind_culture_opt_in` and :func:`rendly.intent.
    bind_intent_profile` — an opt-in record's identity is derived from a validated
    parent, not hand-supplied.
    """
    return DiscoveryProfile(
        user_id=user_profile.user_id,
        tenant_id=user_profile.tenant_id,
        home_locale=home_locale,
        interests=tuple(interests),
        opted_in_at=opted_in_at,
    )


class EventMatch(BaseModel):
    """A single deterministic localized event-discovery match. Immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_user_id: UserId
    subject_tenant_id: TenantId
    event_id: EventId
    event_tenant_id: TenantId
    locale: str
    shared_topics: tuple[str, ...]
    score: int


def _require_bound(profile: Profile, discovery: DiscoveryProfile) -> None:
    if profile.user_id != discovery.user_id or profile.tenant_id != discovery.tenant_id:
        raise ValueError("subject profile/discovery-profile pair do not describe the same user")


def discover_event(
    subject_profile: Profile,
    subject_discovery: DiscoveryProfile,
    listing: EventListing,
) -> EventMatch | None:
    """Score a single subject/listing pair, or ``None`` if no match applies.

    Two-stage, mirrors this codebase's established discipline:
    - LOCALE FILTER (hard requirement — see module docstring "Localized" section):
      ``subject_discovery.home_locale`` must EXACTLY equal ``listing.locale``. A
      listing in a different locale is not "local" to the subject and is refused
      outright, not merely down-ranked.
    - TOPIC OVERLAP (the ranking signal): the subject's ``interests`` and the
      listing's ``topics`` must share at least one tag. Returns ``None`` (never a
      zero-score match, mirroring ``culture.suggest_connection`` / ``intent.
      suggest_match`` / ``career.suggest_trajectory_match``) when the locale
      matches but no topic overlaps — a same-locale, zero-shared-topic event is not
      a discovery match, it is noise.

    Cross-tenant listings ARE matched — see this module's docstring "DELIBERATE
    DIVERGENCE" section; matches ``intent.suggest_match`` / ``peer.suggest_peer``,
    the opposite of ``culture.suggest_connection``.

    Raises ``ValueError`` (mirrors every prior matcher in this module family) if the
    subject profile/discovery-profile pair is internally inconsistent.
    """
    _require_bound(subject_profile, subject_discovery)

    if subject_discovery.home_locale != listing.locale:
        return None

    shared = sorted(set(subject_discovery.interests) & set(listing.topics))
    if not shared:
        return None

    return EventMatch(
        subject_user_id=subject_profile.user_id,
        subject_tenant_id=subject_profile.tenant_id,
        event_id=listing.event_id,
        event_tenant_id=listing.tenant_id,
        locale=listing.locale,
        shared_topics=tuple(shared),
        score=len(shared),
    )


def discover_events(
    subject_profile: Profile,
    subject_discovery: DiscoveryProfile,
    listings: Sequence[EventListing],
    *,
    limit: int = DEFAULT_MATCH_LIMIT,
) -> list[EventMatch]:
    """Rank localized event-discovery matches for ``subject`` against a listing pool.

    Deterministic: ties break on ``event_id`` ascending, so the same input always
    produces the same output (mirrors ``intent.rank_matches`` / ``peer.rank_peers``).
    ``limit`` is clamped to ``[0, MAX_SUGGESTIONS]``; ``listings`` beyond
    ``MAX_LISTINGS`` is rejected outright rather than silently truncated.

    This function does no I/O and does NOT de-duplicate ``listings`` by
    ``event_id`` — a caller passing the same listing twice gets that listing scored
    (and possibly listed) twice, exactly as ``rank_matches``/``rank_peers`` behave.
    """
    if len(listings) > MAX_LISTINGS:
        raise ValueError(f"listings must not exceed {MAX_LISTINGS} entries")
    bounded_limit = max(0, min(limit, MAX_SUGGESTIONS))

    matches = [
        match
        for listing in listings
        if (match := discover_event(subject_profile, subject_discovery, listing)) is not None
    ]
    matches.sort(key=lambda m: (-m.score, m.event_id))
    return matches[:bounded_limit]
