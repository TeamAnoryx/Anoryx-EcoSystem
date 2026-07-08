# ADR-0013 — Virtual Events: a Deterministic, Single-Host Agenda Scheduling Seam (R-013)

Status: Accepted
Date: 2026-07-08
Builds on: ADR-0011 (R-011's group-huddle generalization — the 2-8 participant
P2P cap this task's session capacity reuses in spirit, not by import), ADR-0012
(R-012's precedent for scoping a 🏦 POST-INVESTMENT task down to a pure-domain,
no-persistence, no-REST seam), R-001 D4 (the LOCKED "huddle media is P2P and
NEVER relayed through or content-inspected by Rendly" honesty boundary this task
does not touch or weaken).

## Context

The roadmap names R-013 "Integrated virtual event platform 🏦 POST-INVESTMENT...
Host large-scale online marketing forums, hackathons, industry conferences.
Depends on: R-011 · 28h+ · High." Like R-012 before it, this is a task pulled
from Rendly's 🏦 POST-INVESTMENT tier (Phase 2, "Enterprise culture + events")
into an active build, following the precedent set by O-009/O-010/O-011 and R-012:
ship a deliberately scoped-down seam, not the full named vision, in one task.

Two things bound this task before any design choice is made:

1. **"Large-scale" is aspirational, the delivery is not.** R-001 D4 and ADR-0011
   both lock huddle media as P2P, full-mesh, capped (8 participants) — never an
   SFU or media relay. A genuine "large-scale" virtual event (a marketing forum,
   a hackathon keynote) needs one-to-many delivery, which is architecturally
   impossible to build honestly within that lock: full-mesh WebRTC is O(n^2)
   connections and cannot scale to an audience. Building an SFU here would be
   exactly the "fundamental architecture reversal" ADR-0011's own Alternatives
   section already rejected as out of any one task's license. That capability's
   natural home is R-014 (Encrypted live-streaming infrastructure), a separate,
   already-named roadmap task — not something to smuggle into this one.
2. **"Platform" implies persistence + a wire surface + real huddle binding** —
   all real, multi-week units of work with their own migrations, RLS posture,
   and `contracts/openapi.yaml` additions. Per banked rule 13 ("Lean STEP-0
   forks... default to the minimal option") and ADR-0012's own precedent, this
   task ships the hard, genuinely useful design problem — a validated,
   deterministic multi-session agenda — as a pure-domain seam, and names the
   rest as explicit follow-ups rather than bundling a half-finished version of
   each into one PR.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic single-host scheduling seam; no REST endpoint, no persistence, no live huddle binding, no broadcast)**

`src/rendly/event.py` adds `Event` (an identity: `event_id`, `tenant_id`,
`host_id`, `title`, `created_at`) and `EventSession` (a time-boxed track:
`session_id`, `event_id`, `tenant_id`, `title`, `starts_at`, `ends_at`,
`capacity`), plus `bind_event` (derives `host_id`/`tenant_id` from a real
`Profile`, mirroring `bind_profile`/`bind_culture_opt_in`), `schedule_session`
(validates and mints a new session against a caller-supplied existing agenda),
and `agenda` (a deterministic sort). There is no new migration, no new table, no
new REST route, and no `policy.schema.json` touch (out of scope for this
product entirely, as for every prior Rendly task).

Rejected: A2 (bind sessions to a live `realtime.huddle.Huddle` and actually start
one at its scheduled time). That is a second, independent unit of work (a
scheduler/cron seam, wiring into `HuddleManager.start`, a REST surface to create
events at all) — bundling it here risks shipping either half-finished, exactly
the failure mode ADR-0012 Fork A already named. Rejected: A3 (an SFU/broadcast
delivery layer for "large-scale" audiences). Directly contradicts the LOCKED
R-001 D4 boundary — see Context point 1. The compute-only agenda-scheduling seam
is fully useful and fully testable on its own (exactly as R-002's domain model
was before R-004's persistence, and as R-012's `culture.py` was before its own
deferred persistence/REST halves), so it ships alone.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
single-host, capacity-bounded (2-8 participants per session) AGENDA SCHEDULER —
deterministic overlap validation over caller-supplied session records, nothing
broadcast, nothing persisted, nothing yet wired to a live huddle. "Large-scale...
platform" is the vision name for a future, differently-architected capability;
this task does not claim to be it.

### Fork B — session capacity bound: **B1 (a sibling constant, `MAX_SESSION_CAPACITY = 8`, not an import of `realtime.huddle.MAX_HUDDLE_PARTICIPANTS`)**

The existing codebase's import direction is `realtime -> domain`
(`realtime/*.py` imports `..channel`, `..identifiers`, `..common`, `..profile`
transitively via `authz.py`/`pipeline.py`; nothing under the domain layer
imports `realtime`). `event.py` lives beside `channel.py`/`profile.py`/
`culture.py` in that same domain layer, so importing `realtime.huddle` here
would invert that direction for the sake of sharing one integer. Instead,
`event.py` defines its own `MAX_SESSION_CAPACITY = 8`, documented as
deliberately mirroring (not importing) `MAX_HUDDLE_PARTICIPANTS`, and
`tests/domain/test_event.py` asserts the two constants stay numerically equal
so a future change to one is forced to reconcile the other rather than silently
drifting.

Rejected: B2 (import `MAX_HUDDLE_PARTICIPANTS` directly). Correct in the short
term but sets a precedent of the domain layer reaching into `realtime`, which
every other domain module (`channel.py`, `profile.py`, `culture.py`) has never
done — a layering inversion for one constant is a worse trade than a
test-enforced twin. Rejected: B3 (no cap — accept any `capacity`). A scheduled
session that is never mechanically going to be more than an R-011 group huddle
must not silently promise a capacity the runtime cannot honor.

### Fork C — agenda conflict rule: **C1 (no two sessions on the SAME event may overlap in time, full stop — a single-host agenda)**

One `Event` has exactly one `host_id` (fixed at `bind_event`, mirroring
`Channel.created_by`/`Profile`'s own single-owner shape), and every session
scheduled against it shares that host. The host is one person and — exactly
like `HuddleManager`'s existing "at most one live huddle per user" busy rule —
cannot run two sessions at once, so `schedule_session` rejects any
`[starts_at, ends_at)` window that overlaps an existing session on the same
event. This is the same invariant `realtime.huddle.HuddleManager` already
enforces at huddle-*start* time, applied one layer up at *schedule* time,
before a live huddle exists to check against.

Rejected: C2 (allow overlapping sessions — assume a conference has independent,
parallel-track co-hosts). A genuinely multi-host, parallel-track agenda is a
larger and different feature (who are the OTHER hosts? what authorizes them to
run a track under this event?) with no modeling here yet — `Event.host_id` is
singular precisely so this task does not have to answer that question
un-asked. Named as an explicit non-goal below, not silently implied away.

### Fork D — session/agenda bounds and determinism: **D1 (`MAX_SESSIONS_PER_EVENT = 50`; `agenda()` sorts by `(starts_at, session_id)`)**

Mirrors this codebase's existing bounded-list discipline (`culture.py`'s
`MAX_INTERESTS`/`MAX_CANDIDATES`, `detectors` maxItems 16, `ice_servers` maxItems
16): `schedule_session`'s own O(n) overlap scan against `existing_sessions` is
bounded so an unbounded agenda is never silently accepted from a caller.
`agenda()` produces a deterministic ordering (same input, same output; ties
break on `session_id` ascending) — no hidden randomness or insertion-order
dependence, matching `culture.py.rank_connections`'s own tie-break discipline.

Rejected: D2 (no cap on session count). Same rationale as `MAX_CANDIDATES` in
ADR-0012 Fork D — an unbounded list is an unbounded-cost vector for a caller
that forgets to page its own agenda.

## What is deliberately NOT built here (named, not silently skipped)

- **No persistence.** `Event`/`EventSession` records are not stored; a caller
  must supply the existing agenda (e.g. from an in-memory fixture, or a future
  event store) on every `schedule_session` call. A follow-up task owns
  `rendly.events`/`rendly.event_sessions` Postgres tables (RLS, same posture as
  `channels`/`profiles`) + an Alembic migration.
- **No REST/wire surface.** Nothing in `contracts/openapi.yaml` changes; there
  is no `POST /v1/events` or `POST /v1/events/{event_id}/sessions` yet. A
  follow-up task owns the contract addition and the FastAPI router wiring it to
  this module's pure functions (mirroring how R-008 deferred its own admin-read
  surface, ADR-0008 Fork B).
- **No live huddle binding.** `EventSession.capacity` is validated against
  `MAX_SESSION_CAPACITY` but nothing here calls `HuddleManager.start` when a
  session's `starts_at` arrives — that scheduler/trigger seam is a follow-up.
- **No broadcast / one-to-many audience delivery.** See Context point 1 and
  Fork A. This is the single largest gap between the roadmap's "large-scale...
  platform" name and this delivery, and it is disclosed here precisely so a
  future reader does not mistake this scheduling seam for having solved it —
  that capability belongs to R-014, not a silent extension of this task.
- **No multi-host / parallel-track agendas.** See Fork C.

## Consequences

- A genuinely useful, genuinely tested, capacity-honest scheduling seam exists
  for a future task to persist, expose over HTTP, and eventually bind to real
  huddles and (separately, in R-014) real broadcast delivery — with the hard
  design questions (what counts as a conflict, how capacity is bounded, how
  agenda order is made deterministic) already resolved and covered by
  `tests/domain/test_event.py`.
- No new attack surface is introduced: no new network endpoint, no new table,
  no new migration, no RLS change, no change to huddle signaling or media
  behavior. The security review for this task is scoped accordingly — a pure
  computation over caller-supplied domain objects, with no I/O.
- The roadmap's R-013 checklist line is intentionally NOT marked "the full
  28h+ vision shipped" — it is marked shipped as THIS scoped seam, exactly as
  O-009/O-010/O-011/R-012 were, with the deferred persistence/REST/live-huddle/
  broadcast halves named above as the obvious next slices (the broadcast half
  in particular belongs to the already-named R-014, not a future R-013
  follow-up).
