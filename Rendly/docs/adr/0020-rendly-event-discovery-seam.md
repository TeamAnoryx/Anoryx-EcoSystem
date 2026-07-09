# ADR-0020 — Discovery: a Deterministic, Exact-Locale Event-Discovery Seam over the
Event (R-013) Scheduling Core (R-020)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0013 (R-013's `Event`/`EventSession`/`bind_event` — the scheduling
seam this ADR's `EventListing` binds discovery metadata onto, mirroring how
`EventSession` itself is bound), ADR-0016 (R-016's `IntentProfile`/tag-overlap
discipline and its own Fork A/B scope-down this ADR reproduces unchanged),
ADR-0018 (R-018's composition-seam precedent and its cross-tenant Fork D
reasoning, reused here unchanged for the same B2C-tier reason).

## Context

The roadmap names R-020 "Localized tech-event / hackathon / startup discovery 🏦
POST-INVESTMENT", the fifth task of Rendly's Phase 3 "B2C professional networking
(VISION)" tier (`R-016 -> R-026`, "Depends on: R-004/R-005 + the matching core",
"~10-16h each"). Like R-018/R-019 before it, R-020 has no further roadmap detail
beyond its title — this ADR resolves that title the same way ADR-0016/0017/0018/0019
resolved theirs.

Two things bound this task before any design choice is made, mirroring every prior
ADR in this tier:

1. **"Localized" cannot honestly mean geolocation here.** This codebase has no
   geocoding/mapping integration, no coordinate storage, and no disclosed way to
   validate real-world proximity within one task. The established discipline
   (ADR-0012 §Decision, ADR-0016 §Decision, ADR-0017 §Decision, ADR-0018 §Decision,
   and `culture.py`/`intent.py`/`career.py`/`peer.py`'s own HONESTY BOUNDARY
   docstrings) is that a roadmap task name invoking a capability with no existing
   seam ships as the deterministic, honestly-bounded reduction of that capability —
   here, an opaque locale TAG compared for exact equality, not a distance
   computation.
2. **"Discovery" needs a discoverable item, and one already exists.** R-013 shipped
   `Event` (`event.py`) — "a single-host virtual event" whose own module docstring
   already uses "Q3 Hackathon" as its example title. R-020 does not need to invent a
   new "event" concept; it needs a way to FIND existing `Event` records by locale +
   topic, mirroring how R-018 did not invent a new signal but composed two existing
   ones (ADR-0018 Context).

R-020's differentiator from R-016 is the FILTER-then-RANK shape (not
complementary-tag matching): a subject either can or cannot attend an event in a
given locale (a hard, binary gate — unlike intent's directional overlap), and
THEN topic relevance ranks what is locally discoverable. This two-stage shape has
no exact precedent in this tier and is this ADR's Fork B/C.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic exact-locale filter + topic-overlap ranker over caller-supplied `EventListing` records bound to real `Event`s; no geocoding, no persistence, no REST endpoint, no UI, no ML)**

`src/rendly/discovery.py` adds, mirroring exactly how R-012/R-016/R-017/R-018
shipped their own pure-domain seams:

- `EventListing` — discovery metadata (`locale` + `topics`) bound to a real
  `Event` via `bind_event_listing` (mirrors `EventSession`'s binding to `Event`,
  and `IntentProfile`'s binding to `Profile`).
- `DiscoveryProfile` — a user's explicit opt-in (`home_locale` + `interests`) via
  `bind_discovery_profile` (mirrors `CultureOptIn`/`IntentProfile`).
- `EventMatch` + `discover_event`/`discover_events` (filter + rank — see Fork B/C).

There is no new migration, no new table, no new REST route, and no
`policy.schema.json` touch — identical posture to ADR-0016/0017/0018.

Rejected: A2 (real geocoding — store lat/long, compute haversine distance, accept
a radius parameter). No existing geodata source, no disclosed way to keep it
honestly bounded within one task, and no test could distinguish "correct
distance" from "plausible-looking distance" without a real reference dataset —
the same class of rejection as ADR-0012/0016/0017/0018's own A2 (ML/embeddings).
Rejected: A3 (build the REST endpoint + an event-listing persistence/search index
in the same PR). A second, independent unit of work exactly as every prior ADR in
this tier's own A3/A4 rejections describe.

**HONESTY BOUNDARY (verbatim, non-removable):** "Localized" ships as an OPAQUE
locale tag compared for EXACT string equality — never a coordinate, radius, or
distance computation. A caller who tags two objectively-nearby listings with
different locale strings gets no match; this module trusts its caller's tagging
the same way `culture.py`'s `Interest` and `intent.py`'s `IntentTag` already do.
"Startup discovery" and "hackathon discovery" are not differentiated from generic
tech-event discovery — `Event`/`EventListing` carry no event-type taxonomy, only
free-form `topics` tags a caller may use to encode that distinction (e.g.
`"hackathon"`, `"startup"` as topic values) if it wants to.

### Fork B — locale as a hard filter, not a ranking signal: **B1 (an exact `home_locale`/`listing.locale` mismatch REFUSES the match outright; only topic overlap ranks)**

A subject cannot attend an event in the wrong locale — this is a real, binary
attendance constraint, unlike `culture.py`'s/`intent.py`'s tenant/tag signals
which are genuinely gradable. Treating locale as a THIRD scoring input (e.g.
`score = topic_overlap + locale_bonus`) would let a same-topic, wrong-locale event
occasionally outrank a same-locale, lower-topic-overlap one — actively wrong for a
"localized" discovery feature. `discover_event` therefore checks locale FIRST and
returns `None` immediately on mismatch, before topic overlap is even computed.

Rejected: B2 (locale as a soft ranking signal, e.g. `+10` score for a locale
match). Admits exactly the wrong-locale-events-can-still-appear defect described
above — "localized discovery" showing a subject events they structurally cannot
attend is not a scope-down, it is a correctness bug. Rejected: B3 (fuzzy/prefix
locale matching, e.g. `"us-sf"` matches `"us-*"`). Would require this module to
define a locale HIERARCHY (what does `"us"` mean relative to `"us-sf"`?) with no
disclosed taxonomy to build it from — a real product decision this task is not
positioned to make un-asked, mirroring ADR-0016 Fork D's rejection of an
analogous unbounded-taxonomy proposal.

### Fork C — topic overlap as the ranking signal, "never a zero-score match": **C1 (a same-locale, zero-shared-topic listing is `None`, not a score-0 match)**

Mirrors `culture.suggest_connection`/`intent.suggest_match`/`career.
suggest_trajectory_match`/`peer.suggest_peer`'s own established "never a
zero-score match" discipline unchanged: `shared_topics` must be non-empty for a
`EventMatch` to exist at all. `score = len(shared_topics)`, and `discover_events`
ties-break on `(-score, event_id)` ascending — same input, same output, mirrors
every prior `rank_*` function in this codebase.

Rejected: C2 (return every same-locale listing regardless of topic overlap, with
topic overlap only affecting ORDER). Considered — "browse every local event"
is a legitimate product need — but it is a strictly BROADER feature (a locale-only
feed) than a discovery/matching seam, and conflating the two here would leave no
honest boundary between this task and R-024 (Discovery feed, B2C), which the
roadmap already names as its own task. Keeping `discover_event`'s "never a
zero-score match" contract identical to every sibling matcher in this codebase
is the conservative, consistent choice; a locale-only browse feed is R-024's to
build (see "What is deliberately NOT built here").

### Fork D — tenant scope: **D1 (cross-tenant event discovery is explicitly ALLOWED — no tenant check at all)**

Reproduces ADR-0016 Fork B's, ADR-0017 Fork B's, and ADR-0018 Fork D's reasoning
unchanged: a hackathon/startup event's discovery value is definitionally
CROSS-company (discovering an event hosted by a DIFFERENT tenant is the point,
not an edge case — the opposite of `culture.py`'s same-tenant-only culture
matching). `discover_event`/`discover_events` do not inspect `listing.tenant_id`
relative to the subject's tenant at all.

Rejected: D2/D3 — identical to every prior ADR in this tier's own rejections
(reusing `culture.py`'s refusal "for safety" would silently defeat the feature's
entire point; a per-tenant opt-in allow-list is a real future feature this task
is not positioned to decide un-asked).

### Fork E — bounds + opt-in shape: **E1 (`MAX_TOPICS=16` mirrors `MAX_INTERESTS`/`MAX_TAGS`; `MAX_LISTINGS=500`/`MAX_SUGGESTIONS=50`/`DEFAULT_MATCH_LIMIT=10` mirror `MAX_CANDIDATES`/`MAX_SUGGESTIONS`; one `DiscoveryProfile` covers exactly one `home_locale`)**

Mirrors this codebase's established DoS/cost-guard discipline exactly — the same
magnitudes as every prior tag-bounded opt-in and every prior `rank_*` candidate
pool. A subject wanting discovery across multiple locales opts in multiple times
(one `DiscoveryProfile` per locale) rather than this module admitting an unbounded
per-profile locale list — the same bounded-list-avoidance choice `intent.py`'s/
`culture.py`'s single fixed-shape opt-in objects already make.

Rejected: E2 (a `home_locales: tuple[Locale, ...]` list on one profile). Reopens
an unbounded-list design question (how many locales is "too many"?) with no
disclosed product rationale, when the one-profile-per-locale shape already
composes cleanly with every ranking function here (a caller wanting
multi-locale discovery calls `discover_events` once per `DiscoveryProfile` and
merges client-side) — mirrors this codebase's preference for composing small,
single-purpose objects over widening one object's shape (see `peer.py`'s own
composition-over-widening choice, ADR-0018 Fork A).

## What is deliberately NOT built here (named, not silently skipped)

- **No geocoding/mapping integration.** `Locale` is an opaque string tag; no
  coordinate storage, no distance/radius computation, no locale hierarchy. See
  Fork A/B's HONESTY BOUNDARY.
- **No real B2C consumer identity.** `discover_event`/`discover_events` operate
  over the existing enterprise `Profile` (R-002) plus the new `DiscoveryProfile`
  opt-in as a placeholder actor model, identical posture to `intent.py`/
  `culture.py`/`career.py`/`peer.py`. R-023 (Consumer onboarding) remains the
  natural owner of a real, non-tenant-scoped B2C identity.
- **No persistence.** No new store, no new Alembic migration, and no wiring to a
  real listing catalog. A follow-up task owns an `rendly.event_listings`/
  `rendly.discovery_profiles` table pair + the loader that turns a real `Event`
  catalog into an `EventListing` pool this seam can rank.
- **No REST/wire surface, no frontend.** Nothing in `contracts/openapi.yaml` or
  `contracts/rendly-domain.schema.json` changes, and no frontend package is
  added — Rendly has none, mirroring ADR-0018's own reasoning.
- **No locale-only browse feed.** A same-locale, zero-shared-topic listing is not
  surfaced by this seam (Fork C) — a "show me everything local regardless of
  topic" feed is R-024 (Discovery feed, B2C)'s to build, not duplicated here.
- **No event-type taxonomy.** "Hackathon" vs. "tech event" vs. "startup event" is
  not a first-class field; a caller encodes it, if it wants to, as a `topics` tag.

## Consequences

- A genuinely useful, genuinely tested locale-filtered discovery CORE exists for a
  future persistence/REST/identity/UI/catalog task to build the actual "discovery"
  product on top of, with the hard design questions (locale-as-hard-filter vs.
  soft-signal, zero-topic-overlap handling, cross-tenant handling, DoS bounds)
  already resolved and covered by `tests/domain/test_discovery.py`.
- No new attack surface is introduced: no new network endpoint, no new table, no
  new migration, no RLS change. The security review for this task is scoped
  accordingly — pure computation over caller-supplied domain objects, with no I/O,
  mirroring every prior ADR in this tier's own Consequences.
- The roadmap's R-020 checklist line is intentionally NOT marked "the full
  10-16h localized tech-event/hackathon/startup discovery vision shipped" — it is
  marked shipped as THIS scoped exact-locale filter + topic-overlap ranking seam,
  exactly as O-009/O-010/O-011/R-012/R-013/R-014/R-015/R-016/R-017/R-018/R-019
  were, with the deferred geocoding/identity/persistence/REST/UI/catalog halves
  named above as the obvious next slices.
