# ADR-0014 — Encrypted Live-Streaming: a Key-Epoch Derivation/Rotation Seam (R-014)

Status: Accepted
Date: 2026-07-08
Builds on: ADR-0013 (R-013's own precedent for scoping a 🏦 POST-INVESTMENT task
down to a pure-domain, no-persistence, no-REST seam, and the task that first
named R-014 as the home for "large-scale" delivery), ADR-0011 (R-011's
Alternatives section, which already ruled an SFU "a fundamental architecture
reversal... this task does not have license for" when group huddles first
touched this boundary), R-001 D4 (the LOCKED "huddle media is P2P and NEVER
relayed through or content-inspected by Rendly" honesty boundary this task
does not touch or weaken).

## Context

The roadmap names R-014 "Encrypted live-streaming infrastructure 🏦
POST-INVESTMENT... High-fidelity encrypted live-streaming for confidential
investor updates + global all-hands. Depends on: R-007, R-013 · 28h+ · High."
Following the precedent set by O-009/O-010/O-011/R-012/R-013, this is a 🏦
POST-INVESTMENT task pulled into an active build: ship a deliberately
scoped-down seam, not the full named vision, in one task.

Two things bound this task before any design choice is made, and they
conflict directly with the roadmap name:

1. **"Global all-hands" needs one-to-many delivery; this codebase's
   architecture is LOCKED to P2P.** `contracts/openapi.yaml` states, verbatim:
   "HUDDLES SUPPORT 2-8 PARTICIPANTS (R-011). Media is ALWAYS full-mesh P2P —
   there is no SFU/media-relay tier, regardless of participant count. Rendly
   never sees or forwards huddle media." A genuine broadcast to an
   effectively unbounded "global all-hands" audience requires a media relay
   (SFU) or equivalent fan-out — full-mesh P2P is O(n²) connections and
   cannot scale to that audience. ADR-0011's Alternatives section already
   considered and rejected building an SFU for R-011 itself, calling it
   "a fundamental architecture reversal... with its own dedicated design/
   security review this task does not have license for" — that reasoning
   applies here with, if anything, more force (R-014's own vision needs an
   audience size R-011 never contemplated). This task does NOT build an SFU,
   does NOT lift the R-001 D4 lock, and does NOT claim to deliver one-to-many
   broadcast. That remains a separate, dedicated architecture/security
   decision — outside any single roadmap task's unilateral license — and is
   named as a non-goal below, not silently implied away.
2. **What IS buildable, honestly, within the lock:** a real encrypted-
   streaming feature — even a P2P/full-mesh one — still needs a key-management
   layer: a per-session secret, a way to rotate it (so a departed participant
   loses future access — forward secrecy), and a way to derive independent
   per-participant key material from it (the "insertable streams" pattern
   real E2EE video products layer on top of WebRTC's own mandatory DTLS-SRTP).
   That is a genuine, self-contained, fully-testable cryptographic design
   problem with no dependency on solving (1) first, and it directly extends
   R-013's `EventSession` (the "confidential investor update" case: a small,
   capacity-bounded session is exactly the shape R-011/R-013 already support).

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain key-epoch mint/rotate/derive seam over R-013's `EventSession`; no SFU, no persistence, no wire surface, no media-frame encryption)**

`src/rendly/stream_crypto.py` adds `StreamKeyEpoch` (a per-session master-key
generation: `session_id`, `tenant_id`, `epoch`, `created_at`, `master_key`),
`mint_key_epoch` (epoch 0, derived from a real `EventSession`, fresh
`os.urandom` master key), `rotate_key_epoch` (a new epoch with fresh,
independently-random key material — never derived from the retired epoch),
`derive_participant_key` (HKDF-SHA256 per-participant sub-key), and
`derive_roster_keys` (a bounded batch form). There is no new migration, no new
table, no new REST route, and no `contracts/openapi.yaml`/
`policy.schema.json` touch (out of scope for this product entirely, as for
every prior Rendly task).

Rejected: A2 (an SFU/media-relay broadcast tier for "global all-hands"
audiences). Directly contradicts the LOCKED R-001 D4 boundary — see Context
point 1; not something one task can quietly decide. Rejected: A3 (wire the
epoch/derive functions into `realtime/pipeline.py`/`realtime/ws.py` now, so
live peers actually receive rotated keys over the signaling channel). A
second, independent unit of work (a new signaling message type, e.g.
`stream_key.rotate`, plus the trigger logic deciding WHEN to rotate) —
bundling it here risks shipping either half-finished, exactly the failure
mode ADR-0012/ADR-0013 already named. The key-management seam is fully useful
and fully testable on its own (exactly as R-013's `event.py` shipped before
any live-huddle binding), so it ships alone.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
cryptographic KEY-MANAGEMENT seam — mint/rotate a per-session master key,
derive per-participant sub-keys — for the EXISTING P2P, capacity-bounded (2-8
participant) huddle/session model. Nothing here delivers "high-fidelity...
global all-hands" broadcast; that remains a separate, unbuilt, and
architecturally-locked-out capability. "Encrypted live-streaming
infrastructure" is the vision name for a future, differently-architected
(and, for true broadcast scale, differently-authorized) capability; this task
does not claim to be it.

### Fork B — participant/session capacity bound: **B1 (reuse `event.MAX_SESSION_CAPACITY` directly, not a third sibling constant)**

`event.py`'s own ADR-0013 Fork B declined to import `realtime.huddle.
MAX_HUDDLE_PARTICIPANTS` because that would invert the codebase's
`realtime -> domain` import direction. That concern does not apply here:
`stream_crypto.py` and `event.py` are BOTH domain-layer modules (same layer
`culture.py`/`profile.py`/`channel.py` already live in), so importing
`MAX_SESSION_CAPACITY` from `.event` is ordinary intra-domain sharing, not a
layering inversion — `event.py` itself already imports `.profile` the same
way. A roster this module derives keys for is, mechanically, still bound to
an `EventSession`'s own capacity, so reusing that exact constant (rather than
minting a third number that could drift from both `MAX_HUDDLE_PARTICIPANTS`
and `MAX_SESSION_CAPACITY`) is the more honest bound.

Rejected: B2 (define a new `MAX_STREAM_PARTICIPANTS` sibling constant, tested
for equality like ADR-0013 Fork B did). Correct in spirit but adds a THIRD
number that has to be kept in sync via a test, when a direct import costs
nothing here (no layering concern to avoid, unlike the realtime/domain case).
Rejected: B3 (no cap — accept any roster size). A stream key epoch that is
never mechanically going to serve more than an R-013 session's own bounded
capacity must not silently promise key material for an unbounded audience.

### Fork C — key derivation scheme: **C1 (HKDF-SHA256, salted by `(session_id, epoch)`, info-bound to the participant id; full re-randomization on rotation, not a ratchet)**

Each rotation mints an entirely fresh `os.urandom(32)` master key — it is NOT
derived from the previous epoch's key via a KDF ratchet. This gives simple,
unconditional forward secrecy on rotation (compromising a later epoch's
master key reveals nothing about any earlier epoch, and vice versa, by
construction of independent randomness) at the cost of needing a full
key-material redistribution to every live participant on every rotation
(a follow-up signaling concern, not a cryptographic one). `derive_participant_
key` is deterministic per `(epoch, participant_id)` so two participants who
both hold the same epoch's master key (distributed out-of-band by a future
signaling follow-up) can each compute every other live participant's derived
key locally, with no extra round-trip.

Rejected: C2 (a KDF ratchet — derive each new epoch's master key from the
previous one, e.g. `HKDF(previous.master_key, info=b"rotate")`). Cheaper to
distribute (a participant who already has epoch N can compute epoch N+1
without a fresh out-of-band transfer) but only gives forward secrecy in ONE
direction (a compromised early key lets an attacker compute every later
key by replaying the ratchet) — the opposite of the property a
departed-participant rotation needs (epoch N+1 must be computable by nobody
who only ever held epoch N). Full re-randomization is the correct trade for
"a participant left, rotate them out," which is this task's stated trigger.
Rejected: C3 (derive the participant sub-key from `participant_id` alone,
with no `session_id`/`epoch` salt). Would let the SAME derived key leak across
sessions or across a rotation for the same participant id — defeating the
entire point of per-session, per-epoch scoping.

### Fork D — secret-material hygiene: **D1 (`field(repr=False)` on `master_key`; no `__str__` override needed since dataclasses provide none by default)**

`StreamKeyEpoch.master_key` is real secret material, not a display value.
Using `dataclasses.field(repr=False)` keeps it out of the auto-generated
`repr()` — the same instinct as `auth/keys.py`'s `KeyMaterial`, which only
ever holds parsed `cryptography` key objects (never raw exportable private
bytes) for the same reason. A `StreamKeyEpoch` accidentally landing in a log
line or an uncaught-exception traceback must not leak the key itself.

Rejected: D2 (a full pydantic `BaseModel` like `Event`/`EventSession`, with
`Field(repr=False)`). Considered for consistency with `event.py`'s own
shapes, but `StreamKeyEpoch` carries no wire/JSON-serialization need (it is
never sent over REST/WS, unlike `Event`/`EventSession`) and pydantic's default
`repr` for a `bytes` field would still need the same override — a plain
frozen `dataclass` (matching `realtime/huddle.py`'s own `HuddleArchive`
dataclass, which is likewise a pure in-process value with no wire shape) is
the simpler, equally-safe choice for a type that is pure Python-side state.

## What is deliberately NOT built here (named, not silently skipped)

- **No SFU / broadcast / one-to-many delivery.** See Context point 1 and Fork
  A. This is the single largest gap between the roadmap's "high-fidelity...
  global all-hands" name and this delivery, disclosed here precisely so a
  future reader does not mistake this key-management seam for having solved
  it. Resolving it requires a dedicated architecture/security decision this
  task does not have license to make unilaterally (mirroring ADR-0011's own
  conclusion).
- **No actual media-frame encryption.** Applying a derived key to real RTP
  packets is client-side (WebRTC Insertable Streams or an equivalent media
  pipeline) — entirely outside a Python backend module's reach.
- **No signaling-channel wiring.** Nothing here calls into
  `realtime/pipeline.py`/`realtime/ws.py`; a rotated epoch's per-participant
  keys are never actually distributed to a live peer. A follow-up task owns a
  new signaling message type and the trigger logic (when a participant
  leaves, a session nears its `ends_at`, etc.) that decides WHEN to call
  `rotate_key_epoch`.
- **No persistence.** Epochs are minted/rotated in memory by the caller. A
  follow-up task owns a `rendly.stream_key_epochs` table (rotation history —
  `session_id`, `tenant_id`, `epoch`, `created_at` — explicitly NEVER the
  `master_key` itself) mirroring R-009's archive pattern.
- **No REST/wire surface.** Nothing in `contracts/openapi.yaml` changes.

## Consequences

- A genuinely useful, genuinely tested key-management primitive exists for a
  future task to wire into live signaling, persist an audit trail for, and
  (separately, and only after a dedicated architecture/security decision)
  eventually pair with a real one-to-many delivery tier — with the hard
  design questions already resolved (fresh-randomness-on-rotation forward
  secrecy, per-session/per-epoch/per-participant key scoping, secret-material
  hygiene) and covered by `tests/domain/test_stream_crypto.py`.
- No new attack surface is introduced: no new network endpoint, no new table,
  no new migration, no RLS change, no change to huddle signaling or media
  behavior, no change to the R-001 D4 P2P lock. The security review for this
  task is scoped accordingly — pure computation over caller-supplied
  `EventSession` objects plus the `cryptography` library's own vetted HKDF
  implementation, no I/O.
- The roadmap's R-014 checklist line is intentionally NOT marked "the full
  28h+ high-fidelity/global-all-hands vision shipped" — it is marked shipped
  as THIS scoped key-management seam, exactly as O-009/O-010/O-011/R-012/
  R-013 were, with the deferred SFU-or-equivalent broadcast tier named above
  as requiring its own dedicated future decision, not a routine follow-up.
