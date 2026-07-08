# ADR-0011 — Group Huddles (R-011)

Status: Accepted
Date: 2026-07-08
Builds on: ADR-0007 (R-007, the 1-on-1 signaling design this task extends — NOT replaces),
ADR-0009 (R-009, the huddle hash chain this task extends the canonical field list of),
ADR-0001 D4/D5 (huddle media is P2P and NEVER relayed through Rendly; signaling rides the
same chat WebSocket).
Supersedes: the wire contract's own "1-on-1 ONLY" locks in `contracts/messages.schema.json`
and `contracts/openapi.yaml` (every honesty-boundary sentence naming R-011 as the task that
lifts them) — ADR-0007's Fork A/B/C decisions themselves are NOT superseded; they remain the
exact-2-participant code path, now one case of a more general one.

## Context

R-011 is "Group huddles. Secure multi-party huddles. Depends on: R-007." ADR-0007 already
anticipated this task by name and made a **deliberate, disclosed** choice to keep
`HuddleManager` "keyed 1-on-1 (`caller_id`/`callee_id` scalars, not a participant set) exactly
as the wire's own honesty boundary states group signaling is out of scope" (ADR-0007
Consequences). That choice is now superseded — by this task, not by oversight.

Every layer touched by R-007/R-009 encodes the exactly-2-participants assumption structurally,
not just in prose:
- **Wire contract**: `HuddleInvite.peer_user_id` (scalar, required), `HuddleUpdate.peer_user_id`
  (scalar, required, "the two peers are the inviter and exactly one `peer_user_id`"),
  `SignalSend`/`SignalRelay` (no target field — "the server relays it to the single peer").
  Multiple honesty-boundary sentences across both contract files explicitly name R-011 as the
  task that lifts the lock.
- **`realtime/huddle.py`**: `Huddle.caller_id`/`callee_id` scalar fields, `peer_of()` a
  two-branch `if/elif`, `HuddleManager.start()` takes exactly two named ids.
- **`realtime/pipeline.py`**: the accept/active state-machine heuristic is written entirely in
  terms of "the callee's first signal" / "the caller's first signal"; `_broadcast_huddle_update`
  is a hardcoded 2-tuple loop; `_authorized_huddle` resolves exactly one `peer_id`.
- **`persistence` (`huddles` table, migration `0004`)**: `caller_id`/`callee_id` are two scalar
  FK columns — there is no participant-count column and no junction table.
- **`persistence/hash_chain.py`**: `HUDDLE_CANONICAL_FIELDS` folds in `caller_id`/`callee_id` by
  name, not a participant set.

This task's job is to lift the lock at EVERY one of those layers while leaving the 1-on-1 path
byte-for-byte behaviorally unchanged (every ADR-0007/ADR-0009 test must keep passing
unmodified) — additive extension, not a rewrite.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — wire contract shape | **A1**: ADD optional fields rather than redesign the closed schemas. `HuddleInvite` gains an OPTIONAL `participant_ids` (array of `user_id`, 1–6 items) ALONGSIDE the unchanged, still-required `peer_user_id` — absent/empty `participant_ids` is byte-for-byte the existing 1-on-1 invite. `HuddleUpdate` gains a NEW REQUIRED `participant_ids` array (1–7 items, ALL other participants relative to the recipient) — for a 1-on-1 session this is always the single-element `[peer_user_id]`, so `peer_user_id` keeps its EXACT existing value/meaning for 2-party sessions and is populated as `participant_ids[0]` for groups (a degraded-but-valid single-peer view for a client that hasn't been updated to read the new field). `SignalSend` gains an OPTIONAL `to_user_id` — absent means "the implicit single peer" (unchanged 1-on-1 behavior, zero client-side change required); REQUIRED in practice for any session with 3+ live participants, since full-mesh WebRTC needs a distinct offer/answer/ICE exchange PER PAIR and the server can no longer infer a single implicit target. |
| **B** — participant cap | **B1**: 8 total participants per huddle (1 inviter + `peer_user_id` + up to 6 more in `participant_ids`), enforced by the JSON Schema `maxItems` bound AND server-side. Full-mesh WebRTC (media is P2P, never an SFU — ADR-0001 D4, unchanged) is O(n²) peer connections; 8 is a conservative, disclosed cap matching this codebase's existing bounded-field discipline (`detectors` maxItems 16, `ice_servers` maxItems 16), not a claim that full-mesh scales further. |
| **C** — state machine for 3+ participants | **C1**: the EXISTING `ringing → accepted → active` heuristic (ADR-0007 Fork C) is preserved byte-for-byte for exactly-2-participant sessions — no behavior change, no new state value. For a 3+-participant session, `accepted` is skipped entirely: ANY invitee's first `signal.send` transitions the WHOLE session straight to `active` (there is no single "the callee accepted" moment to key off with 3+ parties — that intermediate state was specifically about the bilateral caller/callee handshake, which does not generalize). This is a stated simplification, mirroring ADR-0007's own "signaling-liveness heuristic, not a media-connected guarantee" honesty boundary — extended, not contradicted. |
| **D** — hangup / leave semantics | **D1**: hangup on an exactly-2-participant session is UNCHANGED (ends the whole session — there is no "leave and the other one continues" for exactly 2 people). Hangup on a 3+-participant session REMOVES the caller from the participant set: if 2+ participants remain, the session STAYS `active` and every remaining participant gets a `huddle.update` with the shrunk `participant_ids` (no new state value — reusing `active` exactly as Fork C's own economy-of-states principle); if exactly 1 remains, the session auto-ends for that last participant too (archived, same as any other `ended` transition) — nobody to talk to alone. A disconnect (`ws.py`'s cleanup) applies the SAME leave-vs-end rule, not a separate one. |
| **E** — invite-time busy/offline handling for N invitees | **E1**: extends ADR-0007 Fork B's fail-closed, non-oracle posture verbatim to N invitees instead of generalizing to a NEW "partial invite" semantic. ALL invitees (`peer_user_id` + `participant_ids`) are checked BEFORE the session is created: every one must have a live connection in the SAME tenant AND not already be in another huddle (the existing per-user busy flag, unchanged — "at most one live huddle per user" generalizes for free since it is keyed by user, not by session size). If ANY invitee fails either check, NO session is created and NOTHING is sent to ANY invitee — only the caller gets a single reply (`huddle_unavailable` for an unreachable/nonexistent invitee, `busy` for a busy one; the FIRST failing invitee in `[peer_user_id, *participant_ids]` order determines which, since revealing "invitee #3 in particular is busy" while staying silent about others is itself a minor information leak the existing non-oracle posture already guards against). Rejected: partial success (creating a session with only the reachable subset) — silently dropping an invitee the caller explicitly named is a worse surprise than a single clear failure, and reintroduces exactly the kind of oracle (which invitees made it in) Fork B was designed to avoid. |
| **F** — persistence shape | **F1**: migration `0005` adds a new `huddle_participants` junction table (`tenant_id, huddle_id, user_id` — composite PK, FK to `huddles` + `users`, RLS, append-only grant, same posture as every other archival table) as the AUTHORITATIVE full participant list for every huddle archived from this task forward (1-on-1 included — a 2-row junction entry for those too, for a uniform read path). `huddles.callee_id` is ALTERED from `NOT NULL` to `NULLABLE` (populated only when the archived session had exactly 2 participants, preserving its exact historical meaning for that case; `NULL` for a genuine 3+-participant session) — `caller_id` stays `NOT NULL` (there is always exactly one inviter). No backfill of historical rows into the new junction table (mirrors ADR-0009's own "chain coverage boundary" precedent: coverage starts at the migration boundary, disclosed, not silently implied as retroactive). **Implementation note**: "the archived session had exactly 2 participants" is evaluated against the FULL historical roster (`realtime/huddle.py` `Huddle.roster` — everyone EVER invited, fixed at `start`), not against whoever is still live at the exact moment a 3+-participant session finally ends (Fork D's leave-by-one/end-at-<=1 mechanics mean the live set at that instant is always <=2 regardless of how many people were originally invited) — a group session's archived record reflects everyone who was ever in it. |
| **G** — hash-chain canonical fields | **G1**: `HUDDLE_CANONICAL_FIELDS` replaces the two named `caller_id`/`callee_id` scalar fields with one `participant_ids` field — a SORTED (deterministic, order-independent) list of every participant id, canonical-JSON-serialized like every other field. This is a strict generalization (a 2-element sorted list carries the exact same information as `caller_id`/`callee_id` did, just order-independently) computed the SAME way for 1-on-1 and group sessions — no branch needed in the hashing code. `HUDDLE_GENESIS_HASH` is UNCHANGED (the same per-tenant chain continues; changing the canonical field list does not break chain LINKAGE — each row's `prev_record_hash` still equals the prior row's `content_hash` regardless of what fed into computing that hash — it only affects whether a FUTURE recomputation of a specific row's hash from raw fields would match, and no `validate_chain`/recompute verifier exists yet per ADR-0009's own "no REST/admin read surface... a follow-up task owns walking/verifying the chain"). **HONESTY BOUNDARY (verbatim, non-removable):** a huddle row archived BEFORE this migration was hashed under the OLD field list (`caller_id`/`callee_id` scalars); a future chain-verifier task must account for the field-list boundary at this migration (mirrors the existing message-chain coverage boundary from ADR-0009) — this is disclosed here, not deferred silently. |
| **H** — REST ICE bootstrap | **H1**: `GET /v1/huddles/ice-servers` needs NO shape change — the response was already a per-caller `ice_servers` array with its own TURN credential; each of the N participants independently calls this endpoint exactly as a 1-on-1 caller does today. Only the `openapi.yaml` prose ("Group/SFU media is out of scope (1-on-1 only)") is updated — the schema itself never encoded the 1-on-1 assumption. |

## What stays unchanged (verify against ADR-0007/ADR-0009 verbatim)

- Huddle media is P2P and NEVER relayed through or content-inspected by Rendly (R-001 D4) —
  full-mesh for groups means MORE P2P connections per session, not a media relay/SFU anywhere.
- "Self-hosted only" ICE/TURN (ADR-0007 Fork D) — unchanged, untouched by this task.
- Signaling metadata still rides the inspection seam exactly as before; still never the media.
- The exactly-2-participant code path is BYTE-FOR-BYTE the R-007 behavior — every existing
  `tests/realtime/test_huddle_ws.py` test must pass with NO modification (proof that this is
  additive, not a rewrite dressed as one).
- Archival remains best-effort, non-blocking, `anyio.CancelScope(shield=True)`-guarded on the
  disconnect path exactly as R-009 built it (ADR-0009 Fork D addendum) — group sessions use the
  identical archive call, just with an N-length participant list instead of two scalars.

## Alternatives considered

- **An SFU (SelectiveForwarding Unit) media relay for groups.** Rejected outright: directly
  contradicts the locked, non-removable R-001 D4 honesty boundary ("huddle MEDIA is P2P and
  NEVER relayed through or content-inspected by Rendly") — building a media relay is not a
  deployment-scale decision this task can quietbly make, it is a fundamental architecture
  reversal with its own dedicated design/security review this task does not have license for.
- **A separate `huddle_participants`-only redesign that drops `caller_id`/`callee_id` from
  `huddles` entirely.** Rejected: would force a backfill or a nullable-everything schema for
  what is still, numerically, the common case (2 participants) and breaks the cheap
  "`SELECT ... WHERE callee_id = ...`"-shaped query an operator or a future admin surface might
  reasonably write. Keeping both (junction table = authoritative + scalar columns = a
  convenience view for the 2-participant case) costs one nullable column and reads better than
  it costs.
- **A JSONB `participant_ids` array column directly on `huddles`** instead of a junction table.
  Rejected: loses the per-participant FK integrity guarantee (`fk_huddles_caller`/`callee`
  already give the DB-level "must be a real same-tenant user" proof for exactly 2; a JSONB array
  gives none of that for N) — the junction table's per-row FK is the direct analog, not a
  downgrade.
- **A brand-new `HuddleUpdate.group_state` enum value replacing `active` for the "a participant
  left, session continues" case.** Rejected (Fork D): reusing `active` costs nothing (the state
  literally IS still active — participants are still live and signaling), and adding an enum
  value is a real wire-contract shape change for no behavioral gain over "the update just
  carries a shorter `participant_ids` array now."
