"""Huddle session state (R-007, generalized to 2-8 participants by R-011) — ephemeral,
single-instance, in-memory.

Mirrors ``ConnectionRegistry``'s stated FORK B boundary (ADR-0005): a huddle is tracked ONLY
for the lifetime of this process, keyed by ``(tenant_id, huddle_id)``. There is no migration and
no new table for the LIVE state — ``identifiers.py`` already notes that ``huddle_id``
"identif[ies] real-time/archival records owned by the [realtime] runtime, not [the R-002]
domain". R-009 persists the SESSION RECORD at the exact ``ended`` transition
(``persistence/huddle_repo.archive_ended_huddle``) — see :class:`HuddleArchive` below.

CROSS-TENANT ISOLATION: exactly like the connection registry, every lookup is keyed by
``tenant_id`` first, and a huddle is only ever created between connections that were resolved
from their OWN tenant sessions — so a huddle can never straddle tenants.

BUSY SEMANTICS: at most one live (non-terminal) huddle per ``(tenant_id, user_id)`` at a time —
you cannot be invited into, or place, a second call while already ringing/accepted/active in
one (ordinary phone-call semantics), regardless of session size. ``active_huddle_id`` gives O(1)
busy detection.

R-011 (ADR-0011): ``Huddle`` is keyed by a participant SET (``live_ids``, 2-8 members) rather
than scalar ``caller_id``/``callee_id`` fields. ``caller_id`` is kept as a SEPARATE, fixed field
(the original inviter — never changes even if that user later leaves) because it is always
exactly one person and the archival schema keeps a NOT NULL column for it (ADR-0011 Fork F).
The exactly-2-participant code path (``callee_id``/``peer_of``) is preserved BYTE-FOR-BYTE for
that case — every ADR-0007 test exercises it unmodified.

HONESTY BOUNDARY (verbatim): "signaling-liveness heuristic, not a media-connected guarantee."
The ``accepted``/``active`` transitions are inferred from WHO sends the first ``signal.send``
after ``ringing``/``accepted`` (see ``realtime/pipeline.py``) — the server never observes real
ICE/DTLS connectivity, because huddle MEDIA is P2P and is never inspected or relayed through
Rendly (R-001 D4 / ADR-0001), for 2 participants OR for a full-mesh group of up to 8 (R-011:
more P2P connections per session, never an SFU). For a 3+-participant session there is no
single bilateral "the callee accepted" moment to key off, so ``accepted`` is skipped entirely:
ANY invitee's first signal transitions the whole session straight to ``active`` (ADR-0011
Fork C).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

# Total participants per huddle (1 inviter + up to 7 invitees) — ADR-0011 Fork B. Full-mesh
# WebRTC (media is P2P, never an SFU) is O(n^2) peer connections; this is a conservative,
# disclosed cap, not a claim that full-mesh scales further. Enforced primarily by the wire
# schema's participant_ids maxItems bound (contracts/messages.schema.json HuddleInvite); this
# constant documents the resulting total and is used for defensive assertions only.
MAX_HUDDLE_PARTICIPANTS = 8


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
    """One live huddle session, 2-8 participants (R-011). Mutable (the manager transitions
    ``state``/``live_ids`` in place).

    ``caller_id`` is the ORIGINAL inviter — fixed for the life of the huddle even if that user
    later leaves a 3+-participant session (ADR-0011 Fork F: the archival ``caller_id`` column
    stays NOT NULL, "there is always exactly one inviter"). ``live_ids`` is the CURRENT set of
    every live participant, caller included while still present; it only ever shrinks (a leave
    removes one id; the huddle is never re-joined once someone leaves). ``roster`` is the FULL
    set of everyone ever invited (fixed at ``start`` — there is no "invite a late joiner"
    feature to grow it) — the archival participant list (Fork F: "the AUTHORITATIVE full
    participant list") is built from ``roster``, not from whoever happens to still be live at
    the moment the session finally ends, so a group session's archived record reflects everyone
    who was ever in it, not just the last 1-2 people standing.
    """

    huddle_id: str
    tenant_id: str
    caller_id: str
    live_ids: frozenset[str]
    roster: frozenset[str]
    state: HuddleState
    created_at: datetime

    @property
    def callee_id(self) -> str | None:
        """The sole OTHER live participant, for an exactly-2-participant session; else ``None``.

        Preserves the exact ADR-0007 1-on-1 meaning: non-``None`` iff there are exactly two live
        participants AND ``caller_id`` is one of them (the common case — a 1-on-1 session, or a
        group session that has shrunk back down to its original inviter + one other person).
        """
        if len(self.live_ids) == 2 and self.caller_id in self.live_ids:
            return next(iter(self.live_ids - {self.caller_id}))
        return None

    def peer_of(self, user_id: str) -> str | None:
        """The OTHER participant relative to ``user_id`` for an exactly-2-participant session,
        or ``None`` (not exactly 2 live participants, or ``user_id`` is not one of them) —
        ambiguous for 3+ (see ``SignalSend.to_user_id``, ADR-0011 Fork A).
        """
        if len(self.live_ids) != 2 or user_id not in self.live_ids:
            return None
        return next(iter(self.live_ids - {user_id}))


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

    def get_active(self, tenant_id: str, user_id: str) -> Huddle | None:
        """The one live huddle ``user_id`` is currently in, if any (disconnect cleanup)."""
        huddle_id = self._by_user.get((tenant_id, user_id))
        if huddle_id is None:
            return None
        return self._huddles.get((tenant_id, huddle_id))

    def start(
        self, *, tenant_id: str, caller_id: str, participant_ids: list[str], now: datetime
    ) -> Huddle:
        """Register a new ringing huddle. Caller is responsible for the busy/reachability
        pre-check (ADR-0011 Fork E) for every id in ``participant_ids`` (1-7 invitees).
        """
        live_ids = frozenset([caller_id, *participant_ids])
        huddle = Huddle(
            huddle_id=new_huddle_id(),
            tenant_id=tenant_id,
            caller_id=caller_id,
            live_ids=live_ids,
            roster=live_ids,
            state=HuddleState.RINGING,
            created_at=now,
        )
        self._huddles[(tenant_id, huddle.huddle_id)] = huddle
        for user_id in live_ids:
            self._by_user[(tenant_id, user_id)] = huddle.huddle_id
        return huddle

    def _release(self, huddle: Huddle) -> None:
        self._huddles.pop((huddle.tenant_id, huddle.huddle_id), None)
        for user_id in huddle.live_ids:
            key = (huddle.tenant_id, user_id)
            if self._by_user.get(key) == huddle.huddle_id:
                del self._by_user[key]

    def transition(self, huddle: Huddle, state: HuddleState) -> None:
        """Move ``huddle`` to ``state`` in place; a terminal state releases it from the manager."""
        huddle.state = state
        if state in TERMINAL_STATES:
            self._release(huddle)

    def remove_participant(self, huddle: Huddle, user_id: str) -> frozenset[str]:
        """Remove ``user_id`` from ``huddle.live_ids`` in place. Returns the PRE-removal set.

        Does NOT transition ``state`` or release the huddle — the caller (``realtime/pipeline.py``
        ``leave_huddle``) decides whether the session stays active (2+ remain) or ends (<=1
        remains) and calls :meth:`transition` accordingly. Only unmaps ``user_id`` here; a
        terminal :meth:`transition` afterward unmaps whoever (0 or 1 people) is left.
        """
        pre_ids = huddle.live_ids
        huddle.live_ids = pre_ids - {user_id}
        key = (huddle.tenant_id, user_id)
        if self._by_user.get(key) == huddle.huddle_id:
            del self._by_user[key]
        return pre_ids
