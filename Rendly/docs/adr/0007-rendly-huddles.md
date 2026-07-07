# ADR-0007 — Rendly 1-on-1 Huddle Signaling + ICE Bootstrap (R-007)

Status: Accepted
Date: 2026-07-07
Builds on: ADR-0001 D5 (signaling rides the SAME chat WebSocket), ADR-0005 (the chat runtime, the
single-instance ``ConnectionRegistry``, the FORK D pipeline placement, the dispatch-table
extension point built FOR this task), ADR-0006 (the channel-authz seam pattern this task
deliberately does NOT reuse — see Fork B below), R-001 (the LOCKED wire contract).

## Context

R-001 already fully specified R-007's wire surface — ``contracts/messages.schema.json`` carries
``HuddleInvite``/``HuddleUpdate``/``HuddleHangup``/``SignalSend``/``SignalRelay`` byte-for-byte,
and ``contracts/openapi.yaml`` already carries ``GET /v1/huddles/ice-servers`` and the
``huddle:initiate`` scope. R-005's dispatcher was deliberately built with this as its extension
point (a ``huddle.*``/``signal.*`` frame received before R-007 answered ``huddle_unavailable``,
never a silent drop). **R-007 adds NO contract change** — it is pure implementation against an
already-locked surface. There is also no migration: ``identifiers.py`` (R-002) already notes that
``huddle_id`` "identif[ies] real-time/archival records owned by the [realtime] runtime, not [the
R-002] domain" — a huddle is ephemeral signaling state, not a persisted entity (R-009 owns
archiving the SESSION RECORD later; that is a separate task).

## Decisions (one per resolved fork)

### Fork A — session topology: **A1 (ephemeral, single-instance, in-memory — mirrors ``ConnectionRegistry``)**
A new ``HuddleManager`` (``realtime/huddle.py``) tracks live huddles by ``(tenant_id, huddle_id)``,
plus one active-huddle-id per ``(tenant_id, user_id)`` for O(1) busy detection. It is NOT
persisted — no table, no migration — matching ADR-0005 Fork B's "single-instance in-memory
registry + documented seam" posture exactly, and matching identifiers.py's framing of
``huddle_id`` as a runtime-owned id. **Stated limitation** (identical to the connection registry):
a second app instance would not see another instance's huddles; cross-instance huddle state
(Redis) is a documented seam, not built (R-010 is single-cluster, so it is unwarranted now).

Rejected: A2 (persist a ``huddles`` table now) — R-009 (immutable archiving) is the task that
turns the SESSION RECORD durable; persisting an ephemeral signaling session ahead of that need
would add a migration + RLS surface for a task that does not require it, and R-009 can start
persisting at the exact `ended`/`declined` transition point this task already computes.

### Fork B — huddle authorization: **B1 (liveness + tenant + scope; NOT the channel-authz matrix)**
A huddle is invited by ``peer_user_id`` (a bare user, not a channel) — the wire's ``HuddleInvite``
carries an OPTIONAL ``channel_id`` with no further documented semantics, so this task treats it as
opaque UI context ONLY (e.g. "call started from #eng"), never an authorization input. Starting a
huddle is gated by: (1) the caller holds ``huddle:initiate`` (the coarse capability, matching the
contract's scope description "Start a 1-on-1 huddle..."), (2) ``peer_user_id != caller`` (1-on-1
structurally requires two distinct people), and (3) the peer has at least one LIVE connection in
the SAME tenant (``ConnectionRegistry.user_connections`` — structurally tenant-scoped, the same
guarantee the chat fan-out rests on). No DB read happens on the invite path. Continuing an
established huddle (``signal.send``/``huddle.hangup``) is gated purely by participation: holding a
``huddle_id`` the manager recognizes for THIS ``(tenant, user)`` pair — a server-minted id hand
delivered only to the two peers on ``ringing`` — IS the proof of authorization; there is no
separate scope re-check on every signal (mirrors how a chat connection, once past the ``chat:read``
handshake gate, does not re-check that scope per frame).

Rejected: B2 (reuse ``realtime/authz.py``'s per-CHANNEL role matrix) — that seam answers "does
this user have PERMISSION_X in CHANNEL_Y", and a huddle is not channel-scoped (ADR-0006 already
disclosed that a DM channel cannot even reach a second participant via any authorized path yet —
building R-007 on top of that gap would inherit it for no benefit). A huddle's authorization
question is simpler and different in kind: "is this a real, reachable, distinct peer in my
tenant, and am I actually one of the two people in THIS specific session" — B1 answers both
without depending on channel membership machinery that R-006 explicitly left incomplete for DMs.

**Fail-closed, non-oracle observations (mirrors ADR-0006's posture):** an offline/nonexistent
peer is indistinguishable from an existing-but-unreachable one (both -> ``huddle_unavailable``, no
separate DB existence check is made); a non-participant probing a real ``huddle_id`` gets the
SAME ``huddle_unavailable`` a bogus id gets (no oracle on whether a huddle exists); a caller
missing ``huddle:initiate`` gets ``unauthorized`` (matches the chat pipeline's scope-deny code).

### Fork C — state machine: **C1 (6-state enum, "accepted"/"active" as a disclosed signaling-liveness heuristic)**
The wire defines 6 ``HuddleUpdate.state`` values but only 3 client frames (``invite``, ``hangup``,
``signal.send`` — no dedicated "accept" frame). This task maps them as:
  * ``invite`` -> **ringing** (both peers notified; a busy target replies **busy** to the CALLER
    ONLY, with a throwaway never-registered ``huddle_id`` — the busy party is never told, matching
    ordinary phone-busy-signal semantics and not registered in the manager, so it cannot leak).
  * The CALLEE's FIRST ``signal.send`` while **ringing** -> **accepted** (their first outbound
    signaling frame is the implicit accept — there is no separate accept message on the wire).
  * The CALLER's FIRST ``signal.send`` while **accepted** -> **active**.
  * ``hangup`` while **ringing** BY THE CALLEE -> **declined**; every other ``hangup`` (the caller
    retracting a ring, or either side leaving accepted/active) -> **ended**. ``ended`` carries the
    ``archival`` object (record_id=huddle_id, seq, DEFINE-ONLY hash fields — R-009 posture,
    identical to chat's ``_archival_meta``); ``declined``/``busy`` do NOT, matching the contract
    description ("archival is present once the huddle reaches a durable (ended) state").
  * A dropped WebSocket (network loss, tab close) with no remaining live connection for that user
    -> **ended** for any huddle they were in (real telephony semantics: a dropped line ends the
    call) — wired into ``ws.py``'s existing disconnect ``finally`` block, gated on "no OTHER live
    connection for this user" so a multi-device user's huddle survives losing one of several tabs.

**HONESTY BOUNDARY (verbatim, non-removable):** "accepted"/"active" are a **signaling-liveness
heuristic**, not a media-connected guarantee — the server never observes real ICE/DTLS
connectivity, because huddle MEDIA is P2P and is never relayed through or inspected by Rendly
(R-001 D4). Two peers reported "active" may still fail to establish media (e.g. symmetric NAT with
no working TURN relay); this task reports the state of the SIGNALING exchange, not the media path.

Rejected: C2 (treat the first signal.send from EITHER side as accept) — collapses the caller's own
offer-sending (which realistically happens WHILE still ringing, before any answer) into a false
"accepted", losing the distinction between "I called" and "they picked up" entirely.

### Fork D — ICE/TURN bootstrap: **D1 (self-hosted only; coturn REST-API HMAC credentials; empty when unconfigured)**
``GET /v1/huddles/ice-servers`` (``realtime/ice.py``, ``EnvIceCredentialProvider``) reads
self-hosted STUN/TURN URLs from env (``RENDLY_STUN_URLS``/``RENDLY_TURN_URLS``) and, if
``RENDLY_TURN_SHARED_SECRET`` is set, mints a short-lived (``ttl_seconds``, default 600s) TURN
credential using the widely-deployed coturn "REST API" static-auth-secret scheme:
``username = "<expiry>:<user_id>"``, ``credential = base64(HMAC-SHA1(secret, username))`` — a
self-hosted coturn verifies it with NO callback to Rendly. STUN needs no credential (it never
relays traffic). Nothing configured -> an EMPTY ``ice_servers`` list (WebRTC can still attempt a
direct/host-candidate connection); TURN URLs configured with NO shared secret -> that entry is
DROPPED, fail-closed (an unauthenticated relay would let anyone tunnel arbitrary traffic).

This is R-007's OWN implementation, not a seam awaiting a later swap-in (unlike the R-008
inspection seam or the D-016 resolver seam) — there is no future roadmap task that replaces it.

**HONESTY BOUNDARY (verbatim, non-removable):** "self-hosted only" — this NEVER falls back to a
third-party public STUN/TURN service (e.g. Google's ``stun.l.google.com``). "Data never leaves"
(R-001's framing for Rendly generally) extends to NAT-traversal hints, not only message content.

Rejected: D2 (public STUN fallback for a better out-of-the-box NAT traversal rate) — directly
contradicts the endpoint's own contract description ("Returns the SELF-HOSTED ICE/TURN
configuration... Rendly never hands out an external meeting link") and the zero-trust framing.

## The three handlers + the ICE endpoint

``realtime/pipeline.py`` adds ``handle_huddle_invite``/``handle_huddle_hangup``/
``handle_signal_send`` to the SAME ``CHAT_HANDLERS`` dispatch table R-005 built (no dispatcher
change). ``handle_signal_send`` relays the peer's SDP/ICE payload FIRST, then announces any state
transition — the direct effect of the frame is never held up behind the secondary broadcast.
``_broadcast_huddle_update`` fans a ``huddle.update`` out to EVERY live connection of BOTH
participants, with ``peer_user_id`` computed relative to each recipient (mirrors
``typing.update``/``presence.update``). ``realtime/rest.py`` adds ``GET /huddles/ice-servers``
alongside the existing chat REST router — no channel/DB involvement at all.

## Consequences

- No contract change, no migration — R-007 is implementation against an already-fully-specified
  surface (a rare, deliberate state for this ecosystem: the contract was locked ahead of the
  builder by design, R-001 D5).
- A huddle has NO connection to channel membership or the R-006 authz matrix — it is possible to
  huddle with any live, distinct, same-tenant peer, independent of shared channels. This is a
  disclosed scope choice (Fork B), not an oversight: it sidesteps the DM-participant-seeding gap
  ADR-0006 already disclosed rather than inheriting it.
- R-009 (immutable archiving) has an exact, already-identified integration point: the ``ended``
  transition in ``handle_huddle_hangup``/the disconnect cleanup path in ``ws.py``, where the
  ``archival`` object is already computed (DEFINE-ONLY hash fields today).
- R-011 (group huddles, post-investment) is unaffected structurally — this task's manager is keyed
  1-on-1 (``caller_id``/``callee_id`` scalars, not a participant set) exactly as the wire's own
  honesty boundary states group signaling is out of scope.
