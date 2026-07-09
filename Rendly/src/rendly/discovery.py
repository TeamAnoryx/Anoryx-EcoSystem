"""Discovery — a deterministic, opaque-locality event-discovery seam over R-013's
event agenda (R-020 = FORK A1/B1/C1/D1).

HONESTY BOUNDARY (verbatim, non-removable): the roadmap names R-020 "Localized
tech-event / hackathon / startup discovery 🏦 POST-INVESTMENT". Three separate
claims are in that title, and only ONE ships here:

- "tech-event / hackathon" DISCOVERY ships: a deterministic filter + rank over
  caller-supplied R-013 ``Event``/``EventSession`` records, additively tagged with
  an opaque locality label (see below) — no ML, no search index, no ranking model.
- "Localized" ships as an OPAQUE, EXACT-MATCH locality tag (e.g. ``"san-francisco"``
  or ``"remote"``), NOT geocoding, NOT distance/radius search, NOT any real-world
  geography validation. This module does not know what a city is; two differently-
  spelled labels for the same real place (``"SF"`` vs ``"san-francisco"``) simply do
  not match — exactly the same opaque-tag discipline ``intent.py``'s/``career.py``'s
  tag fields already use, deliberately not solved here (see Fork C).
- "startup discovery" is NOT BUILT AT ALL. Rendly has no "startup"/company domain
  concept anywhere in this codebase (that concept, if it exists, belongs to
  Delta's CRM domain — a different product, D-013's `crm.py`) — this module
  discovers ``Event`` records only. Silently reinterpreting "startup discovery" as
  "event discovery" would misrepresent the roadmap's own task name; this
  disclosure is that the reinterpretation is deliberate and partial, not complete.

NOT BUILT HERE: geocoding/distance search (see Fork C), a live/persisted event
index (this is a pure filter over a caller-supplied candidate pool, exactly as
``intent.rank_matches``/``career.rank_trajectory_matches`` trust their own caller-
supplied pools), any modification to ``event.py`` itself (R-013's ``Event``/
``EventSession`` are used exactly as shipped — this module ADDS an optional
locality tag via a NEW, additive type, mirroring how ``culture.py`` (R-012) added
``CultureOptIn`` over ``Profile`` without changing ``Profile``), event-visibility/
eligibility gating (a caller decides which events are even offered as candidates —
this module does not know or enforce which events are "public"; see Fork D), no
persistence, no REST/UI, and no "startup" domain (see above).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from .event import Event, EventSession
from .identifiers import EventId, TenantId, UserId

# A sentinel strictly later than any real EventSession.starts_at (event.py requires
# every datetime to be timezone-aware, so this sentinel is too) -- used ONLY as an
# internal sort key so events with no supplied sessions sort last, deterministically,
# without comparing None to a datetime (which Python raises TypeError on).
_SORT_LAST = datetime.max.replace(tzinfo=timezone.utc)

# An opaque locality label: short, non-empty, bounded (mirrors intent.py's
# IntentTag / career.py's CareerStage discipline — no fixed vocabulary, no
# geocoding; exact string equality is the whole matching semantics, see Fork C).
Locality = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# Bounds a subject's locality-interest set (mirrors intent.py's MAX_TAGS).
MAX_LOCALITIES = 16

# Bounds the candidate pool + the result set of a single discovery call (mirrors
# intent.py's/career.py's MAX_CANDIDATES/MAX_SUGGESTIONS at the same magnitudes —
# a DoS/cost guard on the filter+sort below, not a product decision).
MAX_CANDIDATE_EVENTS = 500
MAX_DISCOVERY_RESULTS = 50
DEFAULT_DISCOVERY_LIMIT = 10


class LocalizedEvent(BaseModel):
    """An ``Event``'s opaque locality tag. Immutable, additive — NOT a field on
    ``Event`` itself (see module docstring: this mirrors ``culture.CultureOptIn``'s
    additive-not-modifying relationship to ``Profile``).

    Direct construction with hand-supplied ids is a lower-level primitive (mirrors
    ``EventSession``'s own reservation) NOT validated against a real ``Event``;
    :func:`bind_event_locality` is the canonical, validated path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: EventId
    tenant_id: TenantId
    locality: Locality


def bind_event_locality(event: Event, *, locality: str) -> LocalizedEvent:
    """Build a ``LocalizedEvent`` bound to a real ``Event`` (the canonical path).

    ``event_id``/``tenant_id`` are read FROM the event, mirroring
    :func:`rendly.culture.bind_culture_opt_in` — a tag's identity is derived from
    a validated parent, not hand-supplied.
    """
    return LocalizedEvent(event_id=event.event_id, tenant_id=event.tenant_id, locality=locality)


class DiscoveredEvent(BaseModel):
    """A single discovered event, with its earliest supplied session. Immutable.

    ``next_session_starts_at`` is the earliest ``starts_at`` among whatever
    ``EventSession`` records the caller supplied for this event — NOT "the next
    session from right now" (this module has no clock dependency; see Fork B). A
    caller that wants "upcoming only" filters its own session list to the future
    before calling :func:`discover_events`. ``None`` when no sessions were supplied
    for this event at all.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: EventId
    tenant_id: TenantId
    host_id: UserId
    title: str
    locality: str
    next_session_starts_at: datetime | None


def _require_same_event(event: Event, tag: LocalizedEvent) -> None:
    if event.event_id != tag.event_id or event.tenant_id != tag.tenant_id:
        raise ValueError("event/locality pair do not describe the same event")


def discover_events(
    subject_localities: Sequence[str],
    candidates: Sequence[tuple[Event, LocalizedEvent, Sequence[EventSession]]],
    *,
    limit: int = DEFAULT_DISCOVERY_LIMIT,
) -> list[DiscoveredEvent]:
    """Filter + rank a caller-supplied event pool by opaque locality match.

    Each candidate entry is ``(event, locality_tag, sessions)``. An event is
    included only when its ``locality_tag.locality`` is an EXACT (case-sensitive)
    member of ``subject_localities`` — no partial/fuzzy/geo matching (see Fork C).
    Deterministic: results sort by ``(next_session_starts_at ascending, NULLs
    last, event_id ascending)``, so the same input always produces the same
    output (mirrors ``intent.rank_matches``/``career.rank_trajectory_matches``).

    ``limit`` is clamped to ``[0, MAX_DISCOVERY_RESULTS]``. ``subject_localities``
    beyond ``MAX_LOCALITIES`` and ``candidates`` beyond ``MAX_CANDIDATE_EVENTS``
    are both rejected outright rather than silently truncated.

    Raises ``ValueError`` if any ``(event, locality_tag)`` pair does not describe
    the same event, or if ``sessions`` for a candidate contains a session that
    does not belong to that candidate's ``event`` (mirrors
    ``event.schedule_session``'s own cross-check).

    This function does NOT gate event visibility/eligibility — every element of
    ``candidates`` is trusted as something the subject is already allowed to see
    (see module docstring "NOT BUILT HERE"), exactly as
    ``intent.rank_matches``/``career.rank_trajectory_matches`` trust their own
    candidate pools.
    """
    if len(subject_localities) > MAX_LOCALITIES:
        raise ValueError(f"subject_localities must not exceed {MAX_LOCALITIES} entries")
    if len(candidates) > MAX_CANDIDATE_EVENTS:
        raise ValueError(f"candidates must not exceed {MAX_CANDIDATE_EVENTS} entries")
    bounded_limit = max(0, min(limit, MAX_DISCOVERY_RESULTS))

    wanted = set(subject_localities)
    discovered: list[DiscoveredEvent] = []
    for event, tag, sessions in candidates:
        _require_same_event(event, tag)
        for session in sessions:
            if session.event_id != event.event_id or session.tenant_id != event.tenant_id:
                raise ValueError("sessions must all belong to their candidate's event")

        if tag.locality not in wanted:
            continue

        next_starts_at = min((s.starts_at for s in sessions), default=None)
        discovered.append(
            DiscoveredEvent(
                event_id=event.event_id,
                tenant_id=event.tenant_id,
                host_id=event.host_id,
                title=event.title,
                locality=tag.locality,
                next_session_starts_at=next_starts_at,
            )
        )

    discovered.sort(key=lambda d: (d.next_session_starts_at or _SORT_LAST, d.event_id))
    return discovered[:bounded_limit]
