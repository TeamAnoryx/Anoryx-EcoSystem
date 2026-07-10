"""EventDiscovery — a deterministic, locality-filtered, topic-ranked discovery
seam over R-013's single-host event agenda (R-020 = FORK A1/B1/C1/D1/E1).

HONESTY BOUNDARY (verbatim, non-removable): "Localized tech-event / hackathon /
startup discovery" in the roadmap's task name is NOT implemented here as
geolocation — there is no geocoding, no distance/radius search, no map, no IP/GPS
signal. What ships is a deterministic OPAQUE-TAG locality filter (:class:`EventListing`
carries a caller-assigned ``locality`` tag; :func:`discover_events` includes a
session only when that tag exactly equals the subject's own supplied locality tag,
or the reserved :data:`VIRTUAL_LOCALITY` sentinel) plus a topic-overlap RANKING
(reusing R-016's ``IntentProfile`` as the matching-core signal the roadmap names).
This is a deliberate scope-down of R-020 (~10-16h, 🏦 POST-INVESTMENT, sixth task of
Rendly's B2C professional-networking tier, "Depends on: R-004/R-005 + the matching
core") to a minimal seam, in the same spirit as R-012/R-016/R-017/R-018/R-019's own
scoped deliveries.

NOT BUILT HERE: real geolocation (no lat/long, no radius, no "near me" — "localized"
ships as exact opaque-tag equality only), any crawling/enumeration of real events
(this module ranks a CALLER-SUPPLIED pool, exactly as ``culture.rank_connections`` /
``intent.rank_matches`` / ``peer.rank_peers`` never enumerate a real candidate set
themselves — R-024, Discovery feed, is the named future owner of real candidate-pool
sourcing), any modification of R-013's ``event.py`` (this module is purely additive:
:class:`EventListing` is a new, separate, caller-supplied record keyed to an existing
``Event``, exactly as R-016's ``IntentProfile`` is additive to R-002's ``Profile``
rather than a change to it), persistence for ``EventListing`` (a caller supplies it
each time, mirroring every prior opt-in-style record in this codebase), and any
REST/wire surface or UI.

PRIVACY-CONTROLLED, by construction, not by policy (mirrors ``intent.py``): topic
ranking activates only when the caller supplies a real ``IntentProfile`` for the
subject; a subject who has not opted into R-016's intent matching still gets
locality-filtered results (topic score 0 for all), never an error and never an
inferred signal.

DELIBERATE DIVERGENCE FROM ``intent.suggest_match`` / ``career.suggest_trajectory_
match`` / ``peer.suggest_peer`` / R-019's exposure-grant seam's "never a zero-score
result" rule: :func:`discover_events` DOES include zero-topic-score results. Those
prior modules exclude a zero score because a zero-overlap PAIR has no relationship
at all to report; here, locality match alone (independent of any opted-in topic
signal) is a complete, honest basis for "this is a nearby tech event" — topic
overlap only re-orders an already-eligible result set, it is not a second
eligibility gate stacked on top of locality.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from .event import Event, EventSession
from .identifiers import EventId, SessionId, TenantId
from .intent import IntentProfile

# An opaque locality tag: short, non-empty, bounded (mirrors `culture.Interest` /
# `intent.IntentTag`). No geocoding, no normalization, no distance math — see the
# module docstring's HONESTY BOUNDARY.
LocalityTag = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# A topic/technology tag an event host has labeled a listing with. Mirrors
# `intent.IntentTag` exactly — matched against a subject's `IntentProfile.seeking`.
EventTopicTag = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# Reserved locality value: a listing tagged `VIRTUAL_LOCALITY` is discoverable by a
# subject with ANY locality (a virtual/remote event is, honestly, local to everyone
# — see Fork B). Not a wildcard on the subject's side: a subject cannot supply this
# value to mean "show me everything" — only a LISTING may declare itself virtual.
VIRTUAL_LOCALITY = "virtual"

# Bounded field discipline (mirrors `intent.MAX_TAGS`): a listing's topic list is
# capped so neither storage nor the per-listing scorer below is exposed to an
# unbounded input.
MAX_TOPICS = 16

# Bounds the candidate pool + the result set of a single discovery call (mirrors
# `intent.MAX_CANDIDATES`/`MAX_SUGGESTIONS`) — a DoS/cost guard on the scorer, not a
# product decision about "how many events are useful."
MAX_CANDIDATES = 500
MAX_SUGGESTIONS = 50
DEFAULT_MATCH_LIMIT = 10


class EventListing(BaseModel):
    """A caller-assigned locality + topic label for an existing R-013 ``Event``.

    Immutable, additive, NOT a field on ``Event`` (see module docstring "NOT BUILT
    HERE"). Direct ``EventListing(...)`` construction with hand-supplied ids is a
    lower-level primitive NOT validated against a real ``Event`` (mirrors every
    other opt-in-style record in this codebase); :func:`bind_event_listing` is the
    canonical, validated path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: EventId
    tenant_id: TenantId
    locality: LocalityTag
    topics: tuple[EventTopicTag, ...] = ()

    @field_validator("topics")
    @classmethod
    def _bounded_and_deduped(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_TOPICS:
            raise ValueError(f"topics must not exceed {MAX_TOPICS} tags")
        if len(set(value)) != len(value):
            raise ValueError("topics must not contain duplicates")
        return value


def bind_event_listing(event: Event, *, locality: str, topics: Sequence[str] = ()) -> EventListing:
    """Build an ``EventListing`` bound to a real ``Event`` (the canonical path).

    ``event_id``/``tenant_id`` are read FROM the event, mirroring
    :func:`rendly.intent.bind_intent_profile` — a listing's identity is derived
    from a validated parent, never hand-supplied.
    """
    return EventListing(
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        locality=locality,
        topics=tuple(topics),
    )


class EventDiscoveryResult(BaseModel):
    """A single deterministic discovered event session. Immutable.

    ``matched_topics`` is the subset of the listing's ``topics`` the subject's
    ``IntentProfile.seeking`` overlaps (empty when no ``subject_intent`` was
    supplied, or when nothing overlaps) — reported so a future caller can show
    "why" a result was ranked where it was without recomputing it. ``score`` is
    always ``len(matched_topics)`` — never computed independently, so it can never
    disagree with the reported topics (mirrors ``intent.IntentMatch``'s same
    discipline).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: EventId
    tenant_id: TenantId
    session_id: SessionId
    locality: LocalityTag
    starts_at: datetime
    matched_topics: tuple[EventTopicTag, ...]
    score: int


def _require_bound(event: Event, listing: EventListing) -> None:
    if event.event_id != listing.event_id or event.tenant_id != listing.tenant_id:
        raise ValueError("event/listing pair do not describe the same event")


def _require_session_of_event(event: Event, session: EventSession) -> None:
    if session.event_id != event.event_id or session.tenant_id != event.tenant_id:
        raise ValueError("session does not belong to event")


def _locality_matches(listing_locality: str, subject_locality: str) -> bool:
    return listing_locality == subject_locality or listing_locality == VIRTUAL_LOCALITY


def discover_events(
    subject_locality: str,
    candidates: Sequence[tuple[Event, EventSession, EventListing]],
    *,
    now: datetime,
    subject_intent: IntentProfile | None = None,
    limit: int = DEFAULT_MATCH_LIMIT,
) -> list[EventDiscoveryResult]:
    """Discover and rank upcoming event sessions matching ``subject_locality``.

    Each ``candidates`` entry is validated: the ``EventListing`` must belong to the
    paired ``Event`` (:func:`_require_bound`) and the ``EventSession`` must belong
    to that same ``Event`` (:func:`_require_session_of_event`) — a caller must not
    mix records across events, mirroring ``event.schedule_session``'s own
    same-event requirement. ``candidates`` beyond ``MAX_CANDIDATES`` is rejected
    outright rather than silently truncated.

    A candidate is included only when BOTH hold:
    - ``session.starts_at > now`` (only sessions that have not yet started are
      "discoverable" — this module does no I/O and has no wall-clock of its own,
      so ``now`` is always caller-supplied, never read internally),
    - the listing's locality matches the subject's, per :func:`_locality_matches`
      (exact tag equality, or the listing is tagged :data:`VIRTUAL_LOCALITY` —
      see Fork B).

    Topic overlap does NOT gate inclusion (see module docstring "DELIBERATE
    DIVERGENCE") — it only affects ranking, via ``matched_topics``/``score``.

    Deterministic: ranked by ``(-score, starts_at, session_id)`` — highest topic
    relevance first, then soonest, with a stable final tie-break — so the same
    input always produces the same output. ``limit`` is clamped to
    ``[0, MAX_SUGGESTIONS]``.
    """
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"candidates must not exceed {MAX_CANDIDATES} entries")
    bounded_limit = max(0, min(limit, MAX_SUGGESTIONS))

    seeking = set(subject_intent.seeking) if subject_intent is not None else set()

    results: list[EventDiscoveryResult] = []
    for event, session, listing in candidates:
        _require_bound(event, listing)
        _require_session_of_event(event, session)

        if session.starts_at <= now:
            continue
        if not _locality_matches(listing.locality, subject_locality):
            continue

        matched = sorted(set(listing.topics) & seeking)
        results.append(
            EventDiscoveryResult(
                event_id=event.event_id,
                tenant_id=event.tenant_id,
                session_id=session.session_id,
                locality=listing.locality,
                starts_at=session.starts_at,
                matched_topics=tuple(matched),
                score=len(matched),
            )
        )

    results.sort(key=lambda r: (-r.score, r.starts_at, r.session_id))
    return results[:bounded_limit]
