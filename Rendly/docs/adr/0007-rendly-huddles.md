# ADR-0007 — Rendly 1-on-1 Huddle Signaling (R-007)

Status: Accepted
Date: 2026-07-07
Builds on: ADR-0001 (contract D5 signaling transport + D4 inspection fail-closed), ADR-0005 (async
chat runtime, `ConnectionRegistry`, the inspection seam), ADR-0006 (the single decision point,
per-channel authz matrix). R-001's `contracts/messages.schema.json` and `contracts/openapi.yaml`
already carried the FULL locked wire shape for this feature (`HuddleInvite`/`HuddleUpdate`/
`HuddleHangup`/`SignalSend`/`SignalRelay`, the `Signal` oneOf, and `GET /huddles/ice-servers`) —
R-007 is the server-side implementation against that pre-existing contract, with **no contract
change**.

## Context

R-005/R-006 shipped team chat; R-007 adds the other half of the real-time catalog: low-latency
1-on-1 voice/video huddles. The product promise (roadmap R-007 + the contract's honesty boundary)
is narrow and explicit: **exactly two peers, no external meeting link ever leaves the org, and the
resulting WebRTC media stream is never inspected** (only the chat message content and signaling
*metadata* pass the Sentinel seam — honesty boundary, ADR-0001 D4). Group/multi-party huddles are
R-011 (post-investment) and are out of scope.

The wire catalog defines signaling (`signal.send`/`signal.relay`, an `offer`/`answer`/
`ice-candidate` oneOf) and lifecycle (`huddle.invite`/`huddle.hangup`/`huddle.update`, states
`ringing`/`accepted`/`active`/`declined`/`ended`/`busy`) but — deliberately, per the contract —
does NOT define how the server infers `accepted`/`active`, since there is no separate
`huddle.accept` client frame. R-007 supplies that missing piece as a documented heuristic (Fork C).

## Decisions (one per resolved fork)

### Fork A — session topology: in-memory `HuddleRegistry`, mirrors `ConnectionRegistry` (Fork B)
A NEW single-process, in-memory `HuddleRegistry` (`realtime/huddle.py`) tracks live 1-on-1
sessions by `huddle_id` and enforces ONE active session (`ringing`/`accepted`/`active`) per
`(tenant_id, user_id)` via a busy index. This is the SAME documented SINGLE-INSTANCE limitation
`ConnectionRegistry` already carries (ADR-0005 Fork B) — a second app instance would not see these
sessions; a Redis/shared-state seam is a future extension, not built here. No new persistence: a
huddle's durable record is R-009's job (immutable archiving), so R-007 only assigns the
`archival`-ready ordering fields the contract reserves (`record_id`/`seq`/`created_at`; the hash
fields stay null).

Rejected: persisting huddle sessions to Postgres now — the wire catalog only needs the archival
*fields* reserved (ADR-0001 D3, define-only), and a live call's ephemeral state (ringing/active)
has no audit value until it reaches a terminal state; adding a migration for transient state ahead
of R-009 would be scope creep with no MVP benefit (rule 13, lean STEP-0 forks).

### Fork B — addressing: user-to-user via `ConnectionRegistry.user_connections`, NOT channel-scoped
Huddle invites/updates/signal relays address a **user**, not a channel — added
`ConnectionRegistry.user_connections(tenant_id, user_id)` (a thin accessor over the registry's
existing `_by_user` index) rather than routing huddles through the channel fan-out
`broadcast_channel` uses. `HuddleInvite.channel_id` is OPTIONAL on the wire; when supplied, R-007
additionally requires the caller hold `ChannelAction.READ` on that channel (the SAME single
decision point R-006 built, `authz.authorize`) AND that the invited peer is a member of it — a
channel-scoped huddle cannot be used to reach someone outside the channel. When omitted, any two
same-tenant users holding `huddle:initiate` may huddle directly (Teams/Slack-style direct calling)
— this is a deliberate, minimal-surface reading of an underspecified wire field, stated here for
the record rather than left implicit.

Rejected: requiring a channel for every huddle — the contract's `channel_id` is optional and nothing
in the roadmap ties 1-on-1 calling to channel membership; forcing it would be an undocumented
narrowing of the shipped contract.

### Fork C — state-transition heuristic: signaling-activity-inferred, NOT observed connectivity
There is no `huddle.accept` client frame, so R-007 infers lifecycle progress SOLELY from
`signal.send` activity, using the fixed inviter/peer roles a `Huddle` is created with:
- `ringing` -> `accepted`: the **callee's** (`peer_user_id`'s) first `signal.send` (the inviter may
  signal first — e.g. sending the SDP offer immediately after inviting — that alone does NOT
  accept, since the callee has not responded).
- `accepted` -> `active`: once **both** participants have sent at least one signal.
- Every hangup while still `ringing`, sent by the **callee**, is a `declined`; every other hangup
  (the inviter cancels their own ringing invite, or either side ends `accepted`/`active`) is
  `ended`.

**Honesty boundary (verbatim, non-removable):** the server cannot observe real ICE/media
connectivity — the resulting stream is P2P and never touches the server (ADR-0001 D4). This
heuristic approximates call progress from signaling traffic; it is NOT a proof of a connected
media path. A call that fails to connect at the WebRTC layer after both sides exchange signals
still reads `active` here.

Rejected: a strict SDP-offer/SDP-answer role check (only transition on `kind:"answer"`) — real
WebRTC re-negotiation can send additional offers/answers mid-call, and the contract does not
guarantee the FIRST signal is the SDP payload rather than an ICE candidate (candidates can arrive
before the codec answer in trickle-ICE); gating on "any signal from the callee" is robust to that
and still correctly attributes accept to the answering party via the caller/callee role instead of
message ordering.

### Fork D — signaling inspection: reuses the R-005 `MessageInspector` seam, `huddle_id` stands in for `channel_id`
Per ADR-0001 D4 ("the seam governs chat message content **+ signaling metadata**"), `signal.send`
runs the SAME fail-closed `MessageInspector.inspect` call the chat send pipeline uses — block,
`seam_unavailable`, or a raising inspector all stop the relay (never a silent pass), mirroring the
chat.send fail-closed contract exactly. The seam's `channel_id: str` parameter is NOT optional and
a huddle need not have a `channel_id` of its own (Fork B), so R-007 passes `huddle_id` in that
parameter — a documented, minimal reuse of the existing seam SHAPE rather than adding a second
inspector interface or an R-008-breaking signature change for a distinction the `NoOpMessageInspector`
default cannot observe today. The inspected content is the SDP blob (`offer`/`answer`) or the ICE
candidate line — never the resulting media (honesty boundary, unchanged).

Rejected: a second `HuddleInspector` interface — doubles the seam surface R-008 must implement for
no behavioral difference today (the no-op default treats both identically); can be split later if
R-008's real implementation needs channel-shaped context a huddle cannot supply.

### Fork E — ICE/TURN bootstrap: self-hosted only, coturn REST-API-style short-lived TURN credentials
`GET /v1/huddles/ice-servers` (`realtime/ice.py`, `IceServerConfig.from_env`) returns ONLY
operator-configured self-hosted STUN/TURN endpoints (`RENDLY_STUN_URLS`/`RENDLY_TURN_URLS` env,
comma-separated) — never a third-party meeting URL (the contract's stated honesty boundary: "Rendly
never hands out an external meeting link"). TURN credentials are minted with the standard coturn
`REST API` time-limited convention (`username = "<expiry_ts>:<user_id>"`, `credential =
base64(HMAC-SHA1(RENDLY_TURN_SECRET, username))`) — a widely-deployed non-custom scheme, not a
Rendly invention — so no per-user credential is stored; the TURN server (deployed separately, R-010)
validates the same HMAC. With no `RENDLY_TURN_SECRET` configured, TURN entries are simply omitted
(STUN-only, or empty) — never a fabricated credential.

Rejected: hardcoding a public STUN/TURN provider as a default — even a "free" third-party STUN
server is an external dependency the zero-trust posture does not assume; an unconfigured deployment
gets an empty (honest) `ice_servers` list instead.

### Fork F — disconnect handling: any live-socket drop force-ends the user's active huddle
`realtime/ws.py`'s connection teardown (`finally`) now also calls
`HuddleRegistry.end_active_for_user` before the presence-offline broadcast, notifying the other
participant with a terminal `huddle.update` (`state:"ended"`, archival populated). This mirrors the
EXISTING R-005 presence-offline simplification already accepted in that same function: it fires on
ANY disconnect of ANY of the user's live sockets, even if they hold another connection open
elsewhere (multi-tab is not specially handled — a documented, pre-existing limitation, not a new
one introduced here).

## The single decision points (unchanged, reused)

- `authz.authorize` (R-006) — reused verbatim for the optional `channel_id` gate on
  `huddle.invite`; no new authorization primitive.
- `MessageInspector.inspect` (R-005) — reused verbatim (Fork D) for `signal.send`.
- Identity is token-derived only on every huddle/signal frame (`Connection.user_id`/`tenant_id` off
  the verified JWT), matching the claim-injection defense R-003/R-006 established — a client never
  supplies its own identity in a `huddle.*`/`signal.*` frame body.

## Honesty boundaries (verbatim — non-removable)

1. **1-on-1 only.** No participant list, no group/SFU signaling. Group huddles are R-011
   (post-investment).
2. **Media is never inspected.** Only the chat message content and huddle signaling *metadata*
   (the SDP/ICE payload) pass the Sentinel seam; the resulting P2P WebRTC stream does not.
3. **Self-hosted ICE/TURN only.** No external meeting link (Zoom/Meet/Twilio/etc.) is ever issued;
   an unconfigured deployment returns an empty (not fabricated) `ice_servers` list.
4. **Lifecycle state is inferred, not observed.** `accepted`/`active` approximate call progress
   from signaling activity; the server has no visibility into actual ICE/media connectivity.
5. **Single-instance.** `HuddleRegistry` (like `ConnectionRegistry`) is in-process only; a
   multi-instance deployment needs a future shared-state seam (not built here).
6. **No offline queueing/ringing.** Inviting a peer with no live connection is `huddle_unavailable`
   immediately — there is no push-notification / missed-call surface.

## Consequences

- `pipeline.py`'s dispatch table gains three real client->server handlers
  (`huddle.invite`/`huddle.hangup`/`signal.send`); the two remaining catalog members
  (`huddle.update`/`signal.relay`) stay server->client-only — a client sending one of those still
  gets the pre-existing `huddle_unavailable` fallback (a protocol-misuse case, not a supported op).
- `ws.py`'s disconnect path now performs one extra registry lookup + (on an active huddle) one
  notification send before the existing presence-offline broadcast — negligible cost on the
  already-synchronous teardown path.
- No migration, no contract change, no new `policy_type` — rule 9 does not fire.
- R-008 (real inspection) and R-009 (immutable archiving) are unaffected: R-008 plugs into the
  SAME `MessageInspector` seam this task already wires for signaling (Fork D); R-009 has the
  `archival` ordering fields (`record_id`/`seq`/`created_at`) already populated on every terminal
  `huddle.update` to link a future hash chain over.
