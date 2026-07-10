# ADR-0024 — Discovery Feed (B2C): a Deterministic Cross-Type Composition Seam Over the Four Existing Rankers (R-024)

Status: Accepted
Date: 2026-07-10
Builds on: ADR-0016 (`intent.py`'s Fork A "matching core, not a real B2C
product" scope-down, and its own disclosed limitation naming R-024 as "the
natural home for deciding which candidates a subject is even shown"),
ADR-0017 (`career.py`, same disclosed limitation), ADR-0018 (`peer.py`'s
composition-over-duplication discipline — the direct template this ADR
extends from two composed signals to four), ADR-0020 (`event_discovery.py`,
which additionally named R-024 as "the natural owner of candidate-pool
SOURCING" — the harder half this ADR explicitly does not attempt, see Fork
A), ADR-0021/ADR-0022 (reuse-vs-new-type forks), ADR-0023 (`onboarding.py`'s
"resolve the same fork every predecessor already resolved for its own scope"
framing, reused verbatim below).

## Context

The roadmap names R-024 "Discovery feed (B2C) 🏦 POST-INVESTMENT", the ninth
task of Rendly's Phase 3 "B2C professional networking (VISION)" tier — the
first still-unchecked `R-` line in `anoryx-ecosystem-roadmap-v3.md`'s
checklist as of this run. Four prior ADRs in this exact tier name R-024, in
their own "what is deliberately NOT built here" sections, as the owner of a
specific deferred piece:

- ADR-0016 (`intent.py`, R-016) and ADR-0017 (`career.py`, R-017): "No
  candidate-pool eligibility/discovery... R-024 (Discovery feed) is the
  natural home for deciding which candidates a subject is even shown."
- ADR-0018 (`peer.py`, R-018): the identical disclosed limitation, one level
  up the composition chain.
- ADR-0020 (`event_discovery.py`, R-020): "R-024 (Discovery feed) remains
  the natural owner of candidate-pool sourcing for this and every other
  ranking function in this tier" — the harder claim: not just deciding
  eligibility among a supplied pool, but SOURCING the pool itself (i.e. real
  persistence-backed enumeration of users/events/opportunities).

This ADR is R-024 itself, and faces the same fork every predecessor already
resolved for its own scope (ADR-0023's framing, reused here): ship the full,
disclosed-limitation vision named by four other ADRs, or ship a scoped seam
consistent with this tier's established discipline.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic COMPOSITION of four already-ranked component result lists into one feed; NOT real candidate-pool sourcing, NOT candidate eligibility filtering, no persistence, no REST, no UI)**

`src/rendly/discovery_feed.py` adds `FeedItem` (a tagged union wrapper over
one of `PeerSuggestion` (R-018) / `EventDiscoveryResult` (R-020) /
`OpportunityMatch` (R-021) / `MentorshipMatch` (R-022)) and `compose_feed`
(the merge function: four caller-supplied, already-ranked sequences in,
one interleaved sequence out).

Rejected: A2 (build the real candidate-pool SOURCING ADR-0020 named — query
or enumerate real users/events/opportunities from a persistence layer). No
such persistence layer exists yet for ANY of the four component signals
(`intent_profiles`, `career_goals`, `tech_stack_proficiencies`,
`opportunities`, `event_listings` are all still caller-supplied,
unpersisted objects per their own ADRs' "No persistence" sections) — sourcing
real candidates from nothing would mean inventing that entire store inside
this one task, exactly the undisclosed scope-widening banked rule 13 warns
against, and a strictly larger unit of work than every other seam this tier
has shipped. Rejected: A3 (build the candidate ELIGIBILITY filter ADR-0016/
0017/0018 named — e.g. a mutual-block/opt-out list deciding who a subject is
even shown). Examined and rejected on its own honesty grounds: two of the
four component result types (`EventDiscoveryResult`, and — for the
opportunity POSTER, as opposed to the matching subject —
`OpportunityMatch`) carry no per-candidate USER identity to filter by at
all (an event discovery result identifies a session, not a host; an
opportunity match identifies the opportunity, not its poster) without
modifying those two modules to add one — a cross-module change this task is
not positioned to make un-asked, the same reasoning ADR-0018 Fork E used to
reject adding a third signal to `peer.py`. Rejected: A4 (ship nothing / a
stub, treating R-024 as "just a feed UI"). The roadmap task is real,
schedulable work — four independent ranked result types exist today with no
way to present them as one feed; that gap is closed here, honestly scoped.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
deterministic MERGE of four already-computed, already-ranked result lists —
no candidate sourcing, no eligibility gate, no persistence, no new
personalization signal beyond the four that already exist.

### Fork B — cross-type ordering: **B1 (a fixed round-robin interleave across types in a constant alphabetical order — EVENT, MENTORSHIP, OPPORTUNITY, PEER — never a cross-type numeric score)**

The four component scores are structurally incommensurable: `PeerSuggestion.
score` is a sum of two component match scores (0-2+), `EventDiscoveryResult.
score` is a topic-tag overlap COUNT, `OpportunityMatch.score` is a
skill-tag overlap COUNT, and `MentorshipMatch.score` is a proficiency-RANK
GAP (always 1-3, and the ONLY one of the four with a fixed upper bound by
construction). Summing or otherwise blending these into one number would
require inventing a relative-importance WEIGHTING between "two topic tags
overlap" and "this mentor outranks me by two levels" — exactly the kind of
unrequested, unvalidatable "AI"/personalization framing ADR-0012/0016/0017/
0018's own Fork A already rejected for a single pair of signals, and it
would be worse here composing across four. Round-robin sidesteps the
question honestly: each type's OWN internal order (already produced by its
own component ranker) is preserved untouched, and the only new ordering
decision this module makes — which type goes first when multiple types have
a result available in the same round — is a fixed, disclosed constant, not
a fabricated relevance judgment.

Rejected: B2 (merge by raw score across types, descending). Rejected for the
incommensurability reason above — it would silently favor whichever type's
scoring function happens to produce larger integers, an accidental property
of each component's own scoring internals, not a real relevance signal.
Rejected: B3 (a caller-supplied per-type weight/multiplier). This is the
"per-user feed-mix preference" framing the module docstring's "NOT BUILT
HERE" section names — a real, larger feature (persisted preference,
presumably its own settings surface) this task does not invent un-asked, the
same reasoning ADR-0018 Fork A used to reject inventing "personalization"
generally in this tier. Rejected: B4 (interleave in call-site parameter
order, i.e. whatever order the caller happens to pass the four sequences in
Python). Non-deterministic from the caller's point of view (Python keyword
arguments have no inherent "the caller's order" once bound to named
parameters) and would make the SAME four input lists potentially render
differently depending on unrelated call-site formatting — violates every
other `rank_*`/`discover_*` function's own "same input always produces the
same output" invariant in this codebase.

### Fork C — subject cross-checking: **C1 (`compose_feed` validates that every `peer_suggestions`/`opportunity_matches`/`mentorship_matches` entry's own subject identity matches the supplied `(subject_user_id, subject_tenant_id)`; `event_discoveries` is not cross-checked)**

Mirrors `mentorship.suggest_mentorship_match`'s `_require_bound` and
`privacy.reveal`'s `_check_owner` discipline: a caller passing a peer
suggestion or opportunity match computed for a DIFFERENT subject into this
subject's feed is a caller bug this module can and should catch structurally,
the same way every other cross-referencing function in this codebase does,
rather than silently composing a feed that shows one user another user's
private match results. `mentorship_matches` is checked against the entry's
`mentee_user_id`/`mentee_tenant_id` specifically — this feed always composes
"who can mentor me" results (the subject as mentee), never "who can I
mentor" results, mirroring `rank_mentors`'s own mentee-perspective-only
signature. `event_discoveries` carries no subject identity field at all
(`discover_events` does not require one — see `event_discovery.py`) and is
therefore not cross-checked; this is not a gap, it is that module's own
already-disclosed shape.

Rejected: C2 (no cross-checking at all — trust the caller). Every other
composition/cross-reference function in this codebase (`suggest_peer`,
`suggest_mentorship_match`, `privacy.reveal`) validates its inputs belong
together; silently accepting mismatched subjects here would be the one
inconsistent seam in an otherwise uniformly defensive codebase. Rejected: C3
(re-derive matches instead of trusting caller-supplied ones). Would require
re-running all four component matchers a second time inside this module
instead of composing their outputs, defeating the entire "compose
already-ranked lists" premise of Fork A and duplicating logic this module
should not own.

## What is deliberately NOT built here (named, not silently skipped)

- **No real candidate-pool sourcing.** See Fork A/A2. The single largest
  piece of R-024's four-ADR-disclosed scope remains unbuilt; a future task
  needs the persistence layer named by R-016/R-017/R-021/R-022/R-020's own
  ADRs before it can exist honestly.
- **No candidate eligibility/visibility filtering** (mutual-block, opt-out,
  "who is even shown"). See Fork A/A3 — two of the four component types
  cannot honestly support it without a cross-module change this task does
  not make un-asked.
- **No persistence.** `FeedItem`/`compose_feed` operate on caller-supplied,
  already-computed sequences on every call — no feed-state store, no
  "seen/unseen" tracking, no pagination cursor persistence.
- **No REST/wire surface, no UI/feed component.** Nothing in
  `contracts/openapi.yaml` changes.
- **No cross-type relevance model, no learned weighting, no per-user feed-mix
  preference.** See Fork B — ordering across types is a fixed, disclosed
  constant, never a fabricated score.
- **No premium features / monetization wiring, no creator-economy wiring**
  (R-025/R-026 remain their own, still-unshipped tasks).

## Consequences

- Four previously separate ranked result types (`PeerSuggestion`,
  `EventDiscoveryResult`, `OpportunityMatch`, `MentorshipMatch`) can now be
  rendered as one deterministic feed by a future UI/REST task, with the hard
  design question (how to merge four incommensurable scores honestly)
  already resolved and covered by `tests/domain/test_discovery_feed.py`.
- The still-deferred real candidate-pool sourcing AND eligibility-filtering
  halves remain the two largest pieces of unbuilt B2C-tier scope; this ADR
  names both explicitly (Fork A) rather than letting them continue to be
  referenced only in passing by four OTHER modules' own docstrings, as they
  have been since ADR-0016/ADR-0020.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change, no new identifier type — pure
  computation over caller-supplied domain objects this codebase already
  produces, no I/O.
- The roadmap's R-024 checklist line is intentionally NOT marked "the full
  real B2C discovery-feed vision (candidate sourcing + eligibility +
  personalized ranking + UI) shipped" — it is marked shipped as THIS scoped
  cross-type composition seam, exactly as
  R-012/R-016/R-017/R-018/R-019/R-020/R-021/R-022/R-023 were, with the
  deferred candidate-sourcing/eligibility/REST/UI halves named above as the
  obvious next slice.
