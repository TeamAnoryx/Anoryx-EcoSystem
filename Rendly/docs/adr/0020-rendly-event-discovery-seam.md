# ADR-0020 — Discovery: an Opaque-Locality Event-Discovery Seam over R-013's Agenda (R-020)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0013 (R-013's `Event`/`EventSession` domain — used exactly as
shipped, unmodified), ADR-0012 (R-012's precedent of adding an ADDITIVE opt-in
type over an existing entity rather than modifying it, reproduced here for
`LocalizedEvent` over `Event`), ADR-0016/0017/0018/0019 (the established
scope-down discipline for pure-domain, deterministic, no-persistence,
no-REST/UI seams in this later tier).

## Context

The roadmap names R-020 "Localized tech-event / hackathon / startup discovery
🏦 POST-INVESTMENT". Unlike R-016 ("the matching core" the rest of the B2C
tier explicitly builds on), R-020 has no further roadmap detail beyond its
title, and — unlike R-016 through R-019 — its title bundles THREE distinct
claims that do not share one honest scope-down:

1. **"Localized"** implies geography — a real-world location concept this
   codebase has never modeled (no city/region/coordinate field exists
   anywhere in Rendly's domain, including `event.py`'s `Event`/`EventSession`
   from R-013).
2. **"tech-event / hackathon" discovery** is honestly buildable: R-013
   already shipped a real `Event`/`EventSession` domain type (a single-host
   agenda seam). "Discovery" over an existing domain type — filtering and
   ranking a caller-supplied pool — is exactly the shape R-016/R-017/R-018
   already established for "matching" over `Profile`/opt-in pairs.
3. **"startup discovery"** is a DIFFERENT domain entirely. Rendly has no
   "startup"/company concept anywhere in its codebase — company/deal/pipeline
   concepts belong to Delta's CRM (D-013's `crm.py`), a different product.
   Building a "startup" domain type here, in Rendly, to satisfy this one
   roadmap task's title would be inventing a cross-product concept un-asked —
   the kind of scope-widening banked rule 13 and every ADR in this tier so
   far have avoided.

An unattended run has no human to ask which of these three claims is the
"real" one intended. The conservative, precedent-consistent reading is: ship
what is honestly buildable from what already exists (#2), and name the other
two as explicitly NOT built rather than silently reinterpreting the task.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic filter + rank over caller-supplied `Event`/`EventSession` pools, additively tagged with an opaque locality label; no geocoding, no "startup" domain, no persistence, no REST/UI)**

`src/rendly/discovery.py` adds `LocalizedEvent` (an event's opaque locality
tag — additive, mirrors `culture.CultureOptIn`'s relationship to `Profile`) +
`bind_event_locality`, and `discover_events` (the filter+rank function).
`event.py` itself is NOT modified — `Event`/`EventSession` are imported and
used exactly as R-013 shipped them.

Rejected: A2 (add a `locality`/geo field directly to `Event`). Would modify an
already-shipped, already-tested R-013 type to serve a later, lower-priority
task — the same category of risk ADR-0012 avoided by adding `CultureOptIn` as
a new type rather than touching `Profile`. Rejected: A3 (build real
geocoding/distance search — lat/lng, haversine radius queries). No existing
geo infrastructure in this codebase, no disclosed way to validate real-world
coordinates, and — critically — no product-level decision about what
"nearby" even means (city radius? country? travel time?) that this task is
positioned to make un-asked. Rejected: A4 (invent a "startup"/company domain
type in Rendly to support "startup discovery"). See Context point 3 — this is
Delta's domain, not Rendly's; a genuine cross-product "discover startups
through Rendly" feature is an X- (cross-product) task, not an R- task.
Rejected: A5 (persist `LocalizedEvent` + build the REST endpoint in this
task). Mirrors every prior ADR's identical A3/A4-shaped rejection in this
tier.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
deterministic filter+rank over caller-supplied event data, tagged with an
OPAQUE, EXACT-MATCH locality label — no geocoding, no "startup" discovery, no
persistence, no REST/UI. "Localized tech-event / hackathon / startup
discovery" in the roadmap's task name is NOT what ships in full; the event-
discovery slice, with locality as an opaque tag, is.

### Fork B — locality semantics: **B1 (an opaque, caller-defined string label; exact-match only, no geocoding/fuzzy matching, no fixed vocabulary)**

Mirrors `intent.py`'s `IntentTag` / `career.py`'s `CareerStage` discipline
exactly: a bounded (1..64 char), caller-defined string. `"san-francisco"` and
`"SF"` are different labels and simply do not match — this module does not
attempt to reconcile them.

Rejected: B2 (a fixed enum/vocabulary of known cities). Same rejection
ADR-0017 Fork C already made for a fixed career-stage vocabulary: "who
maintains the map? what happens to an unmapped tag?" — a real product surface
with no disclosed benefit at this scope. Rejected: B3 (geocoded lat/lng +
radius search). See Fork A's rejection of A3 — a genuine, larger feature this
task is not positioned to build.

### Fork C — determinism + clock independence: **C1 (`next_session_starts_at` is the earliest of whatever `EventSession` records the caller supplies — NOT computed relative to wall-clock "now")**

Every prior pure-domain seam in this codebase (`intent.py`, `career.py`,
`peer.py`, `privacy.py`) takes all time-relevant values as explicit
caller-supplied arguments rather than reading the system clock internally —
this module reproduces that discipline. A caller that wants "upcoming events
only" filters its own `EventSession` list to the future before calling
`discover_events`; this function itself has no clock dependency, keeping it
pure, deterministic, and trivially testable without time mocking.

Rejected: C2 (call `datetime.now()` internally to filter to future sessions
before ranking). Would make this the FIRST clock-dependent pure-domain
function in the entire Rendly domain package, breaking the "same input always
produces the same output" invariant every sibling module states explicitly,
and complicating tests with time-mocking this codebase has never needed.

### Fork D — visibility/eligibility + tenant scope: **D1 (no eligibility gating — every candidate is trusted as already-visible; cross-tenant discovery is explicitly ALLOWED)**

Mirrors R-016/R-017/R-018's own disclosed candidate-pool-trust posture and
cross-tenant-allowed reasoning: `discover_events` does not know or enforce
which events are "public" (a caller decides what to offer as candidates), and
does not inspect tenant at all — tech-event/hackathon discovery, like B2C
professional networking, is definitionally cross-company.

Rejected: D2 (restrict discovery to same-tenant events). Would make this
"just an internal event list," not "discovery" in any B2C sense — the
opposite of what a public/community event-discovery feature should do.

## What is deliberately NOT built here (named, not silently skipped)

- **No geocoding/distance search.** See Fork B.
- **No "startup" domain or startup discovery of any kind.** See Fork A's
  rejection of A4 — this remains Delta's domain, not Rendly's.
- **No modification to `event.py`.** `Event`/`EventSession` are used exactly
  as R-013 shipped them; `LocalizedEvent` is purely additive.
- **No persistence.** `LocalizedEvent` is not stored; a caller supplies it
  each time, alongside whatever `Event`/`EventSession` records it already has.
- **No REST/wire surface, no UI.** Nothing in `contracts/openapi.yaml`
  changes.
- **No event-visibility/eligibility gating.** See Fork D — a future
  persistence/REST task owns deciding which events are offered as candidates
  at all.

## Consequences

- A genuinely useful, genuinely tested event-discovery filter+rank seam
  exists over R-013's already-shipped agenda domain, with the hard design
  questions (opaque vs. geocoded locality, clock dependence, eligibility
  trust, cross-tenant scope) already resolved and covered by
  `tests/domain/test_discovery.py`.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change, no modification to `event.py`. The
  security review for this task is scoped accordingly — pure computation
  over caller-supplied domain objects, with no I/O.
- The roadmap's R-020 checklist line is intentionally NOT marked "the full
  localized tech-event/hackathon/startup discovery vision shipped" — it is
  marked shipped as THIS scoped event-discovery seam, with "localized"
  narrowed to an opaque tag and "startup discovery" explicitly named as NOT
  built, exactly as R-012/R-016/R-017/R-018/R-019 each named their own
  deferred halves.
