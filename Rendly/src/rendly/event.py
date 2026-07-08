"""Event — a single-host virtual-event agenda seam (R-013).

HONESTY BOUNDARY (verbatim, non-removable): the roadmap names R-013 "Integrated
virtual event platform... host large-scale online marketing forums, hackathons,
industry conferences" (Heavy, 28h+, 🏦 POST-INVESTMENT). "Large-scale" and
"platform" describe the funded-future vision. What ships here is a deterministic,
pure-domain SCHEDULING seam for a single-host agenda of time-boxed sessions, each
session capacity-bounded to this codebase's existing P2P huddle limit (R-011).
This is a deliberate scope-down in the same spirit as O-009/O-010/O-011 and R-012
(see ADR-0013 §Decision) — not the full platform.

Explicitly NOT built here (named, not silently skipped — see ADR-0013):
- No broadcast / one-to-many delivery / SFU. Every session this module schedules
  is still, mechanically, a group huddle (R-011): full-mesh P2P, capped at
  ``MAX_SESSION_CAPACITY`` participants. A genuine "large-scale" audience (an SFU
  or media-server fan-out) is a fundamental architecture reversal of the LOCKED
  R-001 D4 boundary ("huddle media is P2P and NEVER relayed through Rendly") and
  is out of this task's license — it is the natural shape of R-014 (encrypted
  live-streaming infrastructure), not this one.
- No persistence, no REST/wire surface, no live binding to an actual
  ``realtime.huddle.Huddle``. This is a storage-agnostic computation seam over
  caller-supplied ``EventSession`` records, exactly as R-002 shipped domain-only
  before R-004 added persistence, and exactly as R-012's ``culture.py`` shipped
  its scoring seam with no opt-in store. A follow-up task owns an
  ``rendly.events``/``rendly.event_sessions`` table pair + Alembic migration +
  the FastAPI router that actually calls ``realtime.huddle.HuddleManager.start``
  when a scheduled session's start time arrives.
- No multi-host / parallel-track agenda. One ``Event`` has exactly one
  ``host_id`` (derived from the ``Profile`` that creates it, mirroring
  :func:`rendly.profile.bind_profile`), and every session on that event shares
  the host — so no two of its own sessions may overlap in time (the host cannot
  be in two huddles at once, the same "at most one live huddle per user" rule
  ``realtime.huddle.HuddleManager`` already enforces, one level up at scheduling
  time instead of at huddle-start time). A conference with independently
  schedulable parallel tracks run by different hosts is a real, larger feature
  this module does not attempt.

This module intentionally defines its OWN ``MAX_SESSION_CAPACITY`` constant
rather than importing ``realtime.huddle.MAX_HUDDLE_PARTICIPANTS`` — the codebase's
existing import direction is realtime -> domain (``realtime/*.py`` imports
``..channel``, ``..identifiers``, ``..common``; nothing under ``domain`` imports
``realtime``), and this module lives beside ``channel.py``/``profile.py`` in that
same domain layer. Importing from ``realtime`` here would invert that direction
for a single shared integer. The two constants are asserted equal by
``tests/domain/test_event.py`` so they cannot silently drift apart.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from .common import require_aware_utc
from .identifiers import EventId, SessionId, TenantId, UserId
from .profile import Profile

# Mirrors `ChannelName` (1..128) — an event/session title is a persisted-once label,
# never empty.
Title = Annotated[str, StringConstraints(min_length=1, max_length=128)]

# Deliberately a sibling of `realtime.huddle.MAX_HUDDLE_PARTICIPANTS` (8), not an
# import of it (see module docstring) — every scheduled session is still, at
# huddle-start time, an ordinary R-011 group huddle. A session capacity of 1 is
# not a huddle (nobody to talk to), so the floor is 2.
MAX_SESSION_CAPACITY = 8
MIN_SESSION_CAPACITY = 2
DEFAULT_SESSION_CAPACITY = MAX_SESSION_CAPACITY

# Bounded-list discipline (mirrors `culture.py`'s MAX_INTERESTS/MAX_CANDIDATES,
# `detectors` maxItems 16, `ice_servers` maxItems 16): an agenda is capped so
# neither storage (once a follow-up task adds it) nor the O(n^2) overlap check
# below is exposed to an unbounded input.
MAX_SESSIONS_PER_EVENT = 50


class Event(BaseModel):
    """A single-host virtual event: an identity + title an agenda is scheduled
    against. Immutable. Carries no sessions itself — see module docstring for why
    the agenda is a caller-supplied sequence rather than a field on this object.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: EventId
    tenant_id: TenantId
    host_id: UserId
    title: Title
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "created_at")


class EventSession(BaseModel):
    """One time-boxed track on an ``Event``'s agenda. Immutable.

    Direct construction with hand-supplied ids is a lower-level primitive (mirrors
    ``CultureOptIn``'s same reservation, ADR-0012) that is NOT validated against a
    real ``Event``; :func:`schedule_session` is the canonical, validated path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: SessionId
    event_id: EventId
    tenant_id: TenantId
    title: Title
    starts_at: datetime
    ends_at: datetime
    capacity: int

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _aware(cls, value: datetime, info: ValidationInfo) -> datetime:
        return require_aware_utc(value, info.field_name)

    @model_validator(mode="after")
    def _ends_after_starts(self) -> "EventSession":
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be strictly after starts_at")
        return self

    @field_validator("capacity")
    @classmethod
    def _bounded_capacity(cls, value: int) -> int:
        if not (MIN_SESSION_CAPACITY <= value <= MAX_SESSION_CAPACITY):
            raise ValueError(
                f"capacity must be between {MIN_SESSION_CAPACITY} and "
                f"{MAX_SESSION_CAPACITY} (a scheduled session is a R-011 group "
                "huddle; no broadcast/SFU seam exists here)"
            )
        return value


def new_event_id() -> str:
    """Mint a caller-side event id (canonical dashed-hex UUID v4 — matches the
    ``identifiers.py`` wire-mirroring shape)."""
    return str(uuid.uuid4())


def new_session_id() -> str:
    """Mint a caller-side session id, same shape as :func:`new_event_id`."""
    return str(uuid.uuid4())


def bind_event(host_profile: Profile, *, title: str, created_at: datetime) -> Event:
    """Build an ``Event`` bound to a real ``Profile`` (the canonical construction
    path). ``host_id``/``tenant_id`` are read FROM the profile, mirroring
    :func:`rendly.profile.bind_profile` and :func:`rendly.culture.bind_culture_opt_in`
    — an event's identity is derived from a validated host, never hand-supplied.
    """
    return Event(
        event_id=new_event_id(),
        tenant_id=host_profile.tenant_id,
        host_id=host_profile.user_id,
        title=title,
        created_at=created_at,
    )


def _overlaps(a: EventSession, b: EventSession) -> bool:
    return a.starts_at < b.ends_at and b.starts_at < a.ends_at


def schedule_session(
    event: Event,
    existing_sessions: Sequence[EventSession],
    *,
    title: str,
    starts_at: datetime,
    ends_at: datetime,
    capacity: int = DEFAULT_SESSION_CAPACITY,
) -> EventSession:
    """Schedule one new session on ``event``'s single-host agenda.

    Validates, in order:
    - every entry of ``existing_sessions`` actually belongs to ``event`` (a
      mismatched ``event_id``/``tenant_id`` is refused outright, mirroring
      ``culture.py``'s ``_require_bound`` — a caller must not mix agendas),
    - ``len(existing_sessions) < MAX_SESSIONS_PER_EVENT`` (bounded-list guard),
    - the new session's ``[starts_at, ends_at)`` window does not overlap any
      existing session on the SAME event (the single host cannot be in two
      huddles at once — see module docstring).

    Raises ``ValueError`` on any violation (never silently drops or truncates).
    Returns the new ``EventSession`` with a freshly minted ``session_id`` — the
    caller owns appending it to its own agenda sequence (this function is pure and
    holds no state, exactly as ``culture.py.rank_connections`` holds none).
    """
    if len(existing_sessions) >= MAX_SESSIONS_PER_EVENT:
        raise ValueError(f"event must not exceed {MAX_SESSIONS_PER_EVENT} sessions")

    for existing in existing_sessions:
        if existing.event_id != event.event_id or existing.tenant_id != event.tenant_id:
            raise ValueError("existing_sessions must all belong to the same event")

    candidate = EventSession(
        session_id=new_session_id(),
        event_id=event.event_id,
        tenant_id=event.tenant_id,
        title=title,
        starts_at=starts_at,
        ends_at=ends_at,
        capacity=capacity,
    )

    for existing in existing_sessions:
        if _overlaps(candidate, existing):
            raise ValueError(
                "session overlaps an existing session on this event's single-host " "agenda"
            )

    return candidate


def agenda(sessions: Sequence[EventSession]) -> list[EventSession]:
    """Return ``sessions`` in deterministic agenda order.

    Sorted by ``(starts_at, session_id)`` — the same input always produces the
    same output (no hidden randomness/insertion-order dependence), mirroring
    ``culture.py.rank_connections``'s own tie-break discipline.
    """
    return sorted(sessions, key=lambda s: (s.starts_at, s.session_id))
