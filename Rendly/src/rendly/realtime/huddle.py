"""In-process 1-on-1 huddle session tracker (R-007, mirrors ``registry.py`` FORK B).

A ``Huddle`` is EPHEMERAL runtime state, not a persisted domain record — like
``registry.Connection``, it lives only for the life of this process (SINGLE-INSTANCE, the same
documented limitation ``ConnectionRegistry`` carries: a second app instance would not see these
sessions). Durable archiving of huddle sessions is R-009 (NOT built here); R-007 only assigns the
``huddle_id`` + archival ordering fields the wire ``archival`` object reserves.

LIFECYCLE (``contracts/messages.schema.json`` ``HuddleUpdate.state``): ``ringing`` ->
``accepted`` -> ``active`` -> ``ended``, or ``ringing`` -> ``declined``, or an invite against an
already-busy peer -> ``busy`` (no session is created for a busy reject). Exactly ONE active
session (``ringing``/``accepted``/``active``) is tracked per ``(tenant_id, user_id)`` at a time —
a user already in a session cannot be invited into (or start) a second one, mirroring a real
phone's busy signal.

STATE-TRANSITION HEURISTIC (a documented implementation choice — the wire catalog defines the
states but not their trigger, since there is no separate ``huddle.accept`` client frame): the
server cannot observe real ICE/media connectivity (the resulting stream is P2P and never touches
the server — see the inspection-seam honesty boundary). Progress is inferred SOLELY from
signaling activity: the CALLEE's (``peer_user_id``'s) first ``signal.send`` moves ``ringing`` ->
``accepted`` (the inviter may signal first, e.g. sending the SDP offer immediately after invite —
that alone does NOT move the state, since the callee has not yet responded); once BOTH
participants have sent at least one signal, the session moves ``accepted`` -> ``active``. This
approximates call progress; it is not a proof of a connected media path.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

# The wire-locked state enum (contracts/messages.schema.json HuddleUpdate.state).
ACTIVE_STATES = frozenset({"ringing", "accepted", "active"})
TERMINAL_STATES = frozenset({"declined", "ended", "busy"})


def new_huddle_id() -> str:
    """Mint a server-assigned huddle id (canonical dashed-hex UUID v4 — matches the wire)."""
    return str(uuid.uuid4())


@dataclass
class Huddle:
    """One live 1-on-1 huddle session. Identity (participants) is fixed at creation."""

    huddle_id: str
    tenant_id: str
    inviter_user_id: str
    peer_user_id: str
    channel_id: str | None
    state: str
    # user_ids that have sent >=1 signal.send on this huddle (the accept/active heuristic).
    signaled_by: set[str] = field(default_factory=set)

    def other(self, user_id: str) -> str:
        """The OTHER participant, relative to ``user_id`` (the recipient-relative framing every
        ``huddle.update``/``signal.relay`` frame uses — see ``frames.build_huddle_update``)."""
        return self.peer_user_id if user_id == self.inviter_user_id else self.inviter_user_id

    def participants(self) -> tuple[str, str]:
        return (self.inviter_user_id, self.peer_user_id)

    def is_participant(self, user_id: str) -> bool:
        return user_id in (self.inviter_user_id, self.peer_user_id)


class HuddleRegistry:
    """Single-process, in-memory 1-on-1 huddle tracker (SINGLE-INSTANCE, R-007 FORK B analog).

    Tracks live sessions by ``huddle_id`` and enforces the one-active-session-per-user invariant
    via ``(tenant_id, user_id) -> huddle_id``. A per-tenant monotonic counter supplies the
    archival ``seq`` ordering field (R-009 will later link a hash chain over it); it is
    process-local and resets on restart, matching the SINGLE-INSTANCE limitation stated above.
    """

    def __init__(self) -> None:
        self._huddles: dict[str, Huddle] = {}
        self._active_by_user: dict[tuple[str, str], str] = {}
        self._seq_by_tenant: dict[str, int] = {}

    def next_seq(self, tenant_id: str) -> int:
        seq = self._seq_by_tenant.get(tenant_id, 0)
        self._seq_by_tenant[tenant_id] = seq + 1
        return seq

    def active_huddle_id_for(self, *, tenant_id: str, user_id: str) -> str | None:
        return self._active_by_user.get((tenant_id, user_id))

    def get(self, huddle_id: str) -> Huddle | None:
        return self._huddles.get(huddle_id)

    def create(self, huddle: Huddle) -> None:
        """Register a new session in an ACTIVE state. The caller must have already confirmed
        neither participant holds another active session (the busy check)."""
        self._huddles[huddle.huddle_id] = huddle
        self._active_by_user[(huddle.tenant_id, huddle.inviter_user_id)] = huddle.huddle_id
        self._active_by_user[(huddle.tenant_id, huddle.peer_user_id)] = huddle.huddle_id

    def transition(self, huddle_id: str, state: str) -> Huddle | None:
        """Move a session to ``state``. A TERMINAL state retires it from both indexes."""
        huddle = self._huddles.get(huddle_id)
        if huddle is None:
            return None
        huddle.state = state
        if state in TERMINAL_STATES:
            self._retire(huddle)
        return huddle

    def _retire(self, huddle: Huddle) -> None:
        self._huddles.pop(huddle.huddle_id, None)
        for user_id in huddle.participants():
            key = (huddle.tenant_id, user_id)
            if self._active_by_user.get(key) == huddle.huddle_id:
                del self._active_by_user[key]

    def end_active_for_user(self, *, tenant_id: str, user_id: str) -> Huddle | None:
        """End this user's ACTIVE session (if any) — called on disconnect. Returns the ended
        session (state now ``ended``) so the caller can notify the other participant, or None."""
        huddle_id = self._active_by_user.get((tenant_id, user_id))
        if huddle_id is None:
            return None
        return self.transition(huddle_id, "ended")
