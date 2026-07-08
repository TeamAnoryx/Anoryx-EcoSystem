"""Huddle session state (R-007 1-on-1 + R-011 group) — ephemeral, single-instance, in-memory.

Mirrors ``ConnectionRegistry``'s stated FORK B boundary (ADR-0005): a huddle is tracked ONLY
for the lifetime of this process, keyed by ``(tenant_id, huddle_id)``. There is no migration and
no new table for the LIVE state — ``identifiers.py`` already notes that ``huddle_id``
"identif[ies] real-time/archival records owned by the [realtime] runtime, not [the R-002]
domain". R-009 persists the SESSION RECORD at the exact ``ended`` transition
(``persistence/huddle_repo.archive_ended_huddle``) — see :class:`HuddleArchive` below.

R-011 (ADR-0011 Fork A) generalizes the ORIGINAL 1-on-1 model (``caller_id``/``callee_id``
scalars) to a small, fixed, invite-time PARTICIPANT LIST (``participant_ids``, ordered, element 0
is always the inviter/``caller_id``), capped at :data:`MAX_HUDDLE_PARTICIPANTS`. The 2-participant
case is preserved byte-for-byte: :attr:`Huddle.is_pairwise` branches ``pipeline.py``'s state
machine and archival calls back onto the EXACT R-007 heuristics for that case — R-011 adds a
NEW, simpler heuristic only for 3+ participants (see ``pipeline.py``).

CROSS-TENANT ISOLATION: exactly like the connection registry, every lookup is keyed by
``tenant_id`` first, and a huddle is only ever created among connections resolved from their OWN
tenant sessions — so a huddle can never straddle tenants.

BUSY SEMANTICS: at most one live (non-terminal) huddle per ``(tenant_id, user_id)`` at a time —
you cannot be invited into, or place, a second call while already ringing/accepted/active in
one (ordinary phone-call semantics), and (R-011) inviting a group fails CLOSED as a whole if ANY
named participant — including the inviter — is already busy. ``active_huddle_id`` gives O(1) busy
detection.

HONESTY BOUNDARY (verbatim): "signaling-liveness heuristic, not a media-connected guarantee."
The ``accepted``/``active`` transitions are inferred from WHO sends the first ``signal.send``
after ``ringing``/``accepted`` (see ``realtime/pipeline.py``) — the server never observes real
ICE/DTLS connectivity, because huddle MEDIA is P2P and is never inspected or relayed through
Rendly (R-001 D4 / ADR-0001). This is a stated simplification of the wire's 6-state enum, not a
claim that the two peers are actually media-connected.

HONESTY BOUNDARY (R-011, verbatim): group huddles are FULL-MESH P2P, capped at
:data:`MAX_HUDDLE_PARTICIPANTS` total — there is no SFU/media-relay server, and none is planned by
this task (ADR-0011 §Honest deferrals). The participant list is fixed at invite time for the
huddle's lifetime: there is no mid-call add, and ANY participant hanging up (or dropping their
last connection) ends the WHOLE huddle for every remaining participant — there is no
partial-leave-and-continue. Group (3+ participant) sessions are NOT archived (R-009's
``caller_id``/``callee_id`` schema is pairwise-only); only the classic 2-participant case is.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class HuddleState(StrEnum):
    """Matches ``contracts/messages.schema.json`` ``HuddleUpdate.state`` byte-for-byte."""

    RINGING = "ringing"
    ACCEPTED = "accepted"
    ACTIVE = "active"
    DECLINED = "declined"
    ENDED = "ended"
    BUSY = "busy"


# Terminal states release the huddle from the manager (no further signal/hangup can act on it).
TERMINAL_STATES = frozenset({HuddleState.DECLINED, HuddleState.ENDED})

# R-011 (ADR-0011 Fork B): the inviter + up to MAX_ADDITIONAL_PARTICIPANTS (frames.py) named
# invitees. Disclosed, not unbounded — full-mesh P2P signaling/media cost scales O(N^2), and this
# is the smallest cap that still reads as a genuine "group" (a small team huddle, not a webinar).
MAX_HUDDLE_PARTICIPANTS = 6


def new_huddle_id() -> str:
    """Mint a server-assigned huddle id (canonical dashed-hex UUID v4 — matches the wire)."""
    return str(uuid.uuid4())


@dataclass(frozen=True)
class HuddleArchive:
    """The persisted archival record for an ENDED huddle session (R-009), chained per tenant.

    The huddle-side analog of ``Message``'s archival fields (``realtime/message.py``) — the
    runtime-facing value ``realtime/frames.py`` builds the wire's ``ArchivalMeta`` from. Built
    by ``persistence/huddle_repo.archive_ended_huddle`` (the DB assigns ``seq`` and computes
    the chain under a per-tenant lock; nothing here is guessed client-side or in-memory).
    """

    huddle_id: str
    created_at: datetime
    seq: int
    prev_record_hash: str
    content_hash: str


@dataclass
class Huddle:
    """One live huddle session — 1-on-1 (R-007) or group (R-011). Mutable (the manager
    transitions ``state`` in place).

    ``participant_ids`` is ORDERED and FIXED for the huddle's lifetime (no mid-call add):
    element 0 is always ``caller_id`` (the inviter); the rest are the invitees in the order they
    were named on the wire (``peer_user_id`` first, then ``additional_participant_user_ids``).
    Preserving that order is what lets :meth:`others_of` reproduce R-007's EXACT ``peer_user_id``
    value for the 2-participant case — this is not an arbitrary ordering choice.
    """

    huddle_id: str
    tenant_id: str
    caller_id: str
    participant_ids: tuple[str, ...]  # includes caller_id at index 0; len() in [2, MAX]
    state: HuddleState
    created_at: datetime

    @property
    def is_pairwise(self) -> bool:
        """True for the classic 1-on-1 case (R-007) — branches the state machine + archival."""
        return len(self.participant_ids) == 2

    def others_of(self, user_id: str) -> tuple[str, ...]:
        """Every OTHER participant relative to ``user_id``, in original invite order.

        Empty if ``user_id`` is not a participant. For a 2-participant huddle this is exactly
        R-007's ``peer_of`` (a 1-tuple of the other peer).
        """
        if user_id not in self.participant_ids:
            return ()
        return tuple(p for p in self.participant_ids if p != user_id)


class HuddleManager:
    """Single-instance in-memory registry: ``(tenant_id, huddle_id) -> Huddle``.

    Also tracks the ONE active huddle id per ``(tenant_id, user_id)`` for O(1) busy detection.
    Everything runs on the app's single asyncio event loop (cooperative, no threads — matches
    ``ConnectionRegistry``), so the dict mutations need no lock.
    """

    def __init__(self) -> None:
        self._huddles: dict[tuple[str, str], Huddle] = {}
        self._by_user: dict[tuple[str, str], str] = {}

    def active_huddle_id(self, tenant_id: str, user_id: str) -> str | None:
        return self._by_user.get((tenant_id, user_id))

    def get(self, tenant_id: str, huddle_id: str) -> Huddle | None:
        return self._huddles.get((tenant_id, huddle_id))

    def start(
        self, *, tenant_id: str, caller_id: str, invitee_ids: list[str], now: datetime
    ) -> Huddle:
        """Register a new ringing huddle. Caller is responsible for the busy/liveness pre-checks.

        ``invitee_ids`` is ordered (``peer_user_id`` first, then any
        ``additional_participant_user_ids``) and must be non-empty, caller-free, duplicate-free,
        and bounded — ``pipeline.py`` validates all of that before calling this.
        """
        participant_ids = (caller_id, *invitee_ids)
        huddle = Huddle(
            huddle_id=new_huddle_id(),
            tenant_id=tenant_id,
            caller_id=caller_id,
            participant_ids=participant_ids,
            state=HuddleState.RINGING,
            created_at=now,
        )
        self._huddles[(tenant_id, huddle.huddle_id)] = huddle
        for user_id in participant_ids:
            self._by_user[(tenant_id, user_id)] = huddle.huddle_id
        return huddle

    def _release(self, huddle: Huddle) -> None:
        self._huddles.pop((huddle.tenant_id, huddle.huddle_id), None)
        for user_id in huddle.participant_ids:
            key = (huddle.tenant_id, user_id)
            if self._by_user.get(key) == huddle.huddle_id:
                del self._by_user[key]

    def transition(self, huddle: Huddle, state: HuddleState) -> None:
        """Move ``huddle`` to ``state`` in place; a terminal state releases it from the manager."""
        huddle.state = state
        if state in TERMINAL_STATES:
            self._release(huddle)

    def end_all_for_user(self, tenant_id: str, user_id: str) -> Huddle | None:
        """End this user's one live huddle, if any (disconnect cleanup). Returns it, ended."""
        huddle_id = self._by_user.get((tenant_id, user_id))
        if huddle_id is None:
            return None
        huddle = self._huddles.get((tenant_id, huddle_id))
        if huddle is None:  # pragma: no cover - defensive: the two maps are kept in lockstep
            return None
        self.transition(huddle, HuddleState.ENDED)
        return huddle
