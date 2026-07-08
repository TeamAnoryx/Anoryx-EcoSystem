"""1-on-1 huddle session state (R-007) — ephemeral, single-instance, in-memory.

Mirrors ``ConnectionRegistry``'s stated FORK B boundary (ADR-0005): a huddle is tracked ONLY
for the lifetime of this process, keyed by ``(tenant_id, huddle_id)``. There is no migration and
no new table for the LIVE state — ``identifiers.py`` already notes that ``huddle_id``
"identif[ies] real-time/archival records owned by the [realtime] runtime, not [the R-002]
domain". R-009 persists the SESSION RECORD at the exact ``ended`` transition
(``persistence/huddle_repo.archive_ended_huddle``) — see :class:`HuddleArchive` below.

CROSS-TENANT ISOLATION: exactly like the connection registry, every lookup is keyed by
``tenant_id`` first, and a huddle is only ever created between two connections that were
resolved from their OWN tenant sessions — so a huddle can never straddle tenants.

BUSY SEMANTICS: at most one live (non-terminal) huddle per ``(tenant_id, user_id)`` at a time —
you cannot be invited into, or place, a second call while already ringing/accepted/active in
one (ordinary phone-call semantics). ``active_huddle_id`` gives O(1) busy detection.

HONESTY BOUNDARY (verbatim): "signaling-liveness heuristic, not a media-connected guarantee."
The ``accepted``/``active`` transitions are inferred from WHO sends the first ``signal.send``
after ``ringing``/``accepted`` (see ``realtime/pipeline.py``) — the server never observes real
ICE/DTLS connectivity, because huddle MEDIA is P2P and is never inspected or relayed through
Rendly (R-001 D4 / ADR-0001). This is a stated simplification of the wire's 6-state enum, not a
claim that the two peers are actually media-connected.
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
    """One live 1-on-1 huddle session. Mutable (the manager transitions ``state`` in place)."""

    huddle_id: str
    tenant_id: str
    caller_id: str
    callee_id: str
    state: HuddleState
    created_at: datetime

    def peer_of(self, user_id: str) -> str | None:
        """The OTHER participant relative to ``user_id``, or ``None`` if not a participant."""
        if user_id == self.caller_id:
            return self.callee_id
        if user_id == self.callee_id:
            return self.caller_id
        return None


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

    def start(self, *, tenant_id: str, caller_id: str, callee_id: str, now: datetime) -> Huddle:
        """Register a new ringing huddle. Caller is responsible for the busy pre-check."""
        huddle = Huddle(
            huddle_id=new_huddle_id(),
            tenant_id=tenant_id,
            caller_id=caller_id,
            callee_id=callee_id,
            state=HuddleState.RINGING,
            created_at=now,
        )
        self._huddles[(tenant_id, huddle.huddle_id)] = huddle
        self._by_user[(tenant_id, caller_id)] = huddle.huddle_id
        self._by_user[(tenant_id, callee_id)] = huddle.huddle_id
        return huddle

    def _release(self, huddle: Huddle) -> None:
        self._huddles.pop((huddle.tenant_id, huddle.huddle_id), None)
        for user_id in (huddle.caller_id, huddle.callee_id):
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
