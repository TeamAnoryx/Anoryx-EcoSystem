# ADR-0020 — EventDiscovery: a Deterministic, Locality-Filtered, Topic-Ranked
Discovery Seam over R-013's Event Agenda (R-020)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0013 (R-013's `Event`/`EventSession` single-host agenda — the
domain this task discovers over, unmodified), ADR-0016 (R-016's `IntentProfile`
— "the matching core" this task's topic ranking composes), ADR-0012/0016/0017/
0018/0019 (this tier's shared scope-down discipline).

## Context

The roadmap names R-020 "Localized tech-event / hackathon / startup discovery
🏦 POST-INVESTMENT", the sixth task of Rendly's Phase 3 "B2C professional
networking (VISION)" tier (`R-016 -> R-026`, "Depends on: R-004/R-005 + the
matching core", "~10-16h each"). Like R-017/R-018/R-019 before it, R-020 has
no further roadmap detail beyond its title.

Two things bound this task before any design choice is made, mirroring every
prior ADR in this tier's own Context section:

1. **"Localized" cannot honestly mean geolocation here.** There is no
   geocoding dependency, no lat/long field anywhere in this codebase, no
   distance-math library, and no disclosed way to source real coordinates for
   an `Event` in one task. Building a haversine-distance "near me" search
   without a real location source would be inventing unvalidatable scope —
   the same rejection this tier's ADRs have made repeatedly for "AI"/
   "hyper-personalized" framing (ADR-0012/0016/0017/0018 Fork A).
2. **"Discovery" cannot honestly mean this module sources real events.**
   Every prior ranking function in this tier (`culture.rank_connections`,
   `intent.rank_matches`, `career.rank_trajectory_matches`, `peer.rank_
   peers`) ranks a CALLER-SUPPLIED candidate pool — none of them crawl,
   query, or enumerate a real dataset themselves. R-024 ("Discovery feed
   (B2C)") is a later, separate roadmap task whose obvious job is real
   candidate-pool sourcing; this task does not attempt to preempt it.

R-020's own differentiator from R-016/R-017/R-018/R-019 is that it is the
first task in this tier to attach to R-013's `Event`/`EventSession` domain
rather than composing R-016/017/018's user-matching signals alone — "tech-
event... discovery" names events, not people, as the thing being discovered.
The one genuinely new thing this task can honestly ship, without inventing
geolocation or a real event source, is: a deterministic FILTER (opaque
locality-tag equality) plus a deterministic RANK (topic-tag overlap against
the already-shipped `IntentProfile`) over a caller-supplied pool of upcoming
`(Event, EventSession)` pairs.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic locality filter + topic-overlap ranker; no geocoding, no persistence, no REST/UI, no candidate-pool sourcing)**

`src/rendly/event_discovery.py` adds `EventListing` (a new, additive,
caller-supplied locality+topics label keyed to an existing `Event` — see Fork
B for why this is not a field added to `event.py`) + `bind_event_listing`
(canonical construction, mirrors `bind_intent_profile`) + `EventDiscoveryResult`
+ `discover_events` (the filter+rank function). There is no new migration, no
new table, no new REST route, and no `policy.schema.json` touch — identical
posture to every prior seam in this tier.

Rejected: A2 (real geocoding — lat/long fields, a distance-radius search).
No existing coordinate source, no geocoding dependency, no disclosed way to
validate it honestly in one task — same rejection class as ADR-0012/0016/
0017/0018's own A2. Rejected: A3 (this module sources/crawls real `Event`
records itself, e.g. "all events in the tenant"). Every ranking function in
this codebase takes a caller-supplied pool; inventing an enumeration/query
layer here would preempt R-024's named job and add an unrequested
persistence-query surface. Rejected: A4 (build the REST endpoint + a search
UI in the same PR). A second, independent unit of work, exactly as every
prior ADR in this tier's own A3/A4 rejections describe.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is an
opaque-tag locality FILTER and a topic-overlap RANK over a caller-supplied
event-session pool — no geolocation, no map, no IP/GPS signal, no real event
sourcing. "Localized... discovery" in the roadmap's task name describes the
eventual vision; this task is the deterministic core a future geocoding/
sourcing layer can sit in front of.

### Fork B — where locality lives: **B1 (a new, separate, additive `EventListing` record — `event.py` is NOT modified)**

`Event` (R-013) has no location concept today, and `event.py` is an
already-shipped, already-ADR-governed, already-audited module. Adding a
`locality` field directly to `Event` would modify a prior task's locked
surface for this task's sake — this codebase's established pattern instead
is additive composition (R-016's `IntentProfile` sits beside `Profile`
without changing it; R-019's exposure seam sits beside `Profile`/
`IntentProfile`/`CareerGoal` without changing them). `EventListing` follows
that same pattern: a caller-supplied, `Event`-keyed record validated against
a real `Event` by `bind_event_listing`, exactly mirroring `bind_intent_
profile`'s/`bind_career_goal`'s own "derive identity from a validated parent"
discipline.

Rejected: B2 (add `locality: str | None` directly to `Event`). Technically
possible (an optional field is backward-compatible with existing
constructions) but sets a precedent of later tasks reaching back into
earlier, already-shipped domain modules instead of composing beside them —
every other task in this tier has kept the "additive, never retroactive"
discipline, and this task reproduces it rather than being the first
exception. Rejected: B3 (locality on `EventSession` instead of `Event`,
allowing per-session locations). A plausible real feature (a touring
conference with sessions in different cities) but not something the roadmap
asks for, and it doubles the validation surface (every session would need
its own listing) for no disclosed benefit — `Event`-level locality is the
minimal shape that answers "is this event near me."

### Fork C — locality matching rule: **C1 (exact opaque-tag equality, plus a reserved `VIRTUAL_LOCALITY` sentinel a LISTING may declare)**

A listing is discoverable by a subject when `listing.locality ==
subject_locality` OR `listing.locality == VIRTUAL_LOCALITY`. The virtual
sentinel is a deliberate, minimal product judgment call: a remote/virtual
tech event is honestly "local to everyone" without requiring any distance
math — a single equality branch, not a geocoding feature. It is one-directional
by design: a SUBJECT cannot pass `VIRTUAL_LOCALITY` to mean "show me
everything" — only a listing may declare itself virtual, so the sentinel
cannot be used to bypass the locality filter from the querying side.

Rejected: C2 (no virtual sentinel at all — a virtual event must pick some
arbitrary "locality" string and only matches subjects who happen to query
that exact string). Would make purely-online events effectively
undiscoverable by locality-based search, which is a real product regression
for the common case of a remote hackathon/meetup — the sentinel is a small,
honest fix for that. Rejected: C3 (fuzzy/substring locality matching, e.g.
"san-francisco" matches "san-francisco-bay-area"). Silent fuzzy matching
without a defined normalization scheme (casefolding? hyphenation? aliasing
"sf" to "san-francisco"?) is an undisclosed product decision with no
established convention in this codebase (`intent.py`/`culture.py`'s own tag
matching is exact, case-sensitive, unnormalized) — exact equality is the
conservative, consistent choice.

### Fork D — inclusion vs. ranking (topic score): **D1 (topic overlap does NOT gate inclusion — only locality + upcoming-time do; a zero-topic-score result is still returned)**

This is the one deliberate divergence from `intent.suggest_match`'s /
`career.suggest_trajectory_match`'s / `peer.suggest_peer`'s / R-019's shared
"never a zero-score result" rule. Those functions model a PAIRWISE
relationship between two people — a zero-overlap pair has, honestly, no
relationship to report, so excluding it is correct. `discover_events` models
something different: "what nearby tech events exist," where locality alone
(independent of any opted-in topic signal) is a complete, honest basis for
inclusion. A subject who has not opted into R-016's `IntentProfile` at all
still deserves to see nearby events — treating "no topic signal" as
"no result" would make locality-only browsing impossible, which is not what
"discovery" means.

Rejected: D2 (require `subject_intent` and at least one topic match, mirroring
the sibling modules' zero-score exclusion). Would make event discovery
strictly WORSE than plain locality browsing for any subject who has not
opted into intent matching, and conflates two independent axes (is this
event near me / is this event relevant to my interests) into one gate.

### Fork E — bounds, time filter, and determinism: **E1 (caller-supplied `now`, no wall-clock reads; reuse `MAX_CANDIDATES=500`/`MAX_SUGGESTIONS=50`/`DEFAULT_MATCH_LIMIT=10`; rank by `(-score, starts_at, session_id)`)**

Mirrors this codebase's own no-internal-wall-clock discipline (grep confirms
every `datetime.now()`/`utcnow()` call in this codebase lives in the
`realtime`/`auth`/`persistence` runtime layers, never in a pure-domain
module) — `discover_events` takes `now: datetime` as a required keyword
argument rather than reading the system clock, so the same input always
produces the same output. Only sessions with `starts_at > now` are
discoverable (a session starting AT exactly `now` is excluded — it is no
longer "upcoming"). Candidate/result bounds reuse this tier's established
magnitudes (`intent.py`/`career.py`/`peer.py`'s own `MAX_CANDIDATES`/
`MAX_SUGGESTIONS`) for the same DoS/cost-guard reasoning, not loosened or
tightened without a disclosed justification. Results rank by
`(-score, starts_at, session_id)` — highest topic relevance first, then
soonest-starting, with `session_id` as a final stable tie-break — so ranking
never depends on input order.

Rejected: E2 (rank by `starts_at` only, ignoring topic score). Would waste
the one matching-core signal the roadmap names as a dependency. Rejected:
E3 (raise the bounds because "events" are a different entity than "people").
No disclosed justification for a different magnitude — the existing bounds
size a DoS guard on a pairwise/per-candidate scorer, and that reasoning does
not change with the entity type being scored.

## What is deliberately NOT built here (named, not silently skipped)

- **No real geolocation.** No lat/long, no distance/radius search, no map, no
  IP/GPS signal — see Fork A/C. A future task (not yet named on the roadmap)
  owns real geocoding if the product ever needs it.
- **No real event sourcing/enumeration.** `discover_events` ranks a
  caller-supplied pool; it does not query, crawl, or page through a real
  event dataset. R-024 (Discovery feed) remains the natural owner of
  candidate-pool sourcing for this and every other ranking function in this
  tier.
- **No modification of `event.py`.** `EventListing` is additive — see Fork B.
- **No persistence for `EventListing`.** No new store, no new Alembic
  migration. A follow-up task owns wiring `EventListing` (and `event.py`'s
  own already-named deferred `Event`/`EventSession` persistence) to a real
  table.
- **No REST/wire surface, no frontend.** Nothing in `contracts/openapi.yaml`
  changes, no frontend package is added.

## Consequences

- A genuinely useful, genuinely tested locality-filter + topic-rank CORE
  exists for a future geocoding/persistence/REST/UI/event-sourcing task to
  build the actual "discovery" experience on top of, with the hard design
  questions (where locality lives, the virtual-event sentinel, inclusion vs.
  ranking, bounds, determinism) already resolved and covered by
  `tests/domain/test_event_discovery.py`.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change, and `event.py` itself is
  untouched. The security review for this task is scoped accordingly — pure
  computation over caller-supplied domain objects, with no I/O and no
  internal wall-clock read.
- The roadmap's R-020 checklist line is intentionally NOT marked "the full
  10-16h localized tech-event discovery vision shipped" — it is marked
  shipped as THIS scoped filter+rank seam, exactly as
  O-009/O-010/O-011/R-012/R-013/R-016/R-017/R-018/R-019 were, with the
  deferred geolocation/persistence/REST/UI/sourcing halves named above as
  the obvious next slices.
