# ADR-0021 — Opportunity: a Deterministic Skill-Overlap Matching Seam over
R-016's Intent-Matching Core (R-021)

Status: Accepted
Date: 2026-07-10
Builds on: ADR-0016 (R-016's `IntentProfile` — "the matching core" this task
composes, and its own explicit naming of R-021 as one of the tasks that core
is meant to be reusable for), ADR-0017 (the same explicit naming, repeated),
ADR-0018/0019/0020 (this tier's shared scope-down discipline, composition-not-
modification pattern, and each seam's own resolved "never a zero-score match"
vs. "zero-score still included" fork).

## Context

The roadmap names R-021 "Skill-based opportunity matching (freelance +
full-time) 🏦 POST-INVESTMENT", the sixth task of Rendly's Phase 3 "B2C
professional networking (VISION)" tier (`R-016 -> R-026`, "Depends on:
R-004/R-005 + the matching core", "~10-16h each"). Like R-018/R-019/R-020
before it, R-021 has no further roadmap detail beyond its title — but unlike
those three, R-021 is not undirected: ADR-0016 and ADR-0017 both already name
it explicitly as a future consumer of R-016's `IntentProfile.offering` skill
tags ("`seeking`/`offering` skill TAGS... R-021 skill-based opportunity
matching", ADR-0017 §Context item 2; "R-021 skill-based opportunity
matching... is expected to build on" the matching core, ADR-0016 §Context).
This ADR is that build.

Two things bound this task before any design choice is made, mirroring every
prior ADR in this tier's own Context section:

1. **"Skill-based... matching" cannot honestly mean a job board.** There is no
   application/hiring workflow, no listings marketplace, no resume-parsing
   dependency anywhere in this codebase, and no disclosed way to build one
   honestly in one task — the same rejection class this tier's ADRs have made
   repeatedly for "the full vision" framing.
2. **This is the first task in this tier where the "candidate" being ranked is
   not a person.** Every prior ranking function (`culture.rank_connections`,
   `intent.rank_matches`, `career.rank_trajectory_matches`, `peer.rank_peers`)
   scores one `Profile` against another. `event_discovery.discover_events`
   (R-020) was the first to rank a non-person entity (an event session), and
   this task is the second — an `Opportunity` posting has no `IntentProfile`
   of its own to score reciprocally against; only the SUBJECT side carries the
   opt-in signal.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic skill-overlap scorer; no job board, no application workflow, no persistence, no REST/UI, no resume parsing)**

`src/rendly/opportunity.py` adds `Opportunity` (a new, additive, caller-
supplied posting record — see Fork B for why this does not touch
`intent.py`) + `bind_opportunity` (canonical construction, mirrors
`bind_event`/`bind_intent_profile`) + `OpportunityMatch` + `suggest_
opportunity_match` / `rank_opportunities` (the skill-overlap scorer). There is
no new migration, no new table, no new REST route, and no `policy.schema.json`
touch — identical posture to every prior seam in this tier.

Rejected: A2 (a real job-board/listings marketplace with an application
pipeline). A second, independent, much larger unit of work with no disclosed
scope in one task — the same rejection class as every prior "A4: build the
REST endpoint + UI in the same PR" in this tier. Rejected: A3 (resume/bio-text
parsing to derive skills automatically). No existing text-extraction
dependency, no training data, no disclosed way to validate it honestly in one
task — same rejection class as ADR-0012/0016/0017's own "no ML" A2 forks.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
deterministic SKILL-OVERLAP scorer between a caller-supplied `Opportunity`
posting's `required_skills` and a subject's already-shipped R-016
`IntentProfile.offering` tags — no job board, no application/hiring workflow,
no resume parsing, no learned relevance. "Skill-based opportunity matching" in
the roadmap's task name describes the eventual vision; this task is the
deterministic core a future listings/persistence/REST/UI layer can sit in
front of.

### Fork B — where required skills live: **B1 (a new, separate, additive `Opportunity` record — `intent.py` is NOT modified)**

A posting's required skills are a property of the OPPORTUNITY, not of any
`Profile` or `IntentProfile` — `IntentProfile` models what a PERSON is
seeking/offering, and overloading it with a third, posting-scoped field would
conflate two different entities' data the same way ADR-0017 Fork B rejected
overloading `IntentProfile` with a career stage. `Opportunity` follows this
tier's established additive-composition pattern (R-016's `IntentProfile` sits
beside `Profile` without changing it; R-020's `EventListing` sits beside
`Event` without changing it): a wholly new, caller-supplied record, bound to a
posting `Profile` via `bind_opportunity` exactly as `bind_event`/`bind_event_
listing` derive identity from a validated parent.

Rejected: B2 (add an `offering`-shaped field to `Opportunity` and reuse
`intent.suggest_match`'s directional seeker/offerer scoring instead of a new
function). An opportunity does not itself "seek" or "offer" in the
complementary sense `intent.py` models (a posting does not have unmet needs
matched against what it can give in return) — it simply REQUIRES skills, a
plain set membership relationship, not a two-directional complementary one.
Reusing `suggest_match`'s shape here would misrepresent what is actually being
compared. Rejected: B3 (skills live on `Profile` directly, as a fixed field
alongside `team`). Would modify a prior task's locked surface (R-002's
`Profile`) for this task's sake, breaking the "additive, never retroactive"
discipline this tier has kept since R-016.

### Fork C — matching semantics: **C1 (plain set-intersection: `subject_intent.offering & opportunity.required_skills`; never a zero-score match)**

Unlike `intent.suggest_match`'s directional complementary scoring
(seeking-vs-offering in both directions) or `career.suggest_trajectory_match`'s
directional stage equality, opportunity matching is a single, symmetric
question: does what the subject can DO (`IntentProfile.offering`) cover what
the posting REQUIRES (`Opportunity.required_skills`)? A plain set intersection
answers this directly, with no directionality to model on the opportunity
side (a posting has no reciprocal "offering" of its own to match against).

`suggest_opportunity_match` returns `None` (never a zero-score match) when
there is no skill overlap. This is a **deliberate divergence from
`event_discovery.discover_events`'s "zero-score still included" rule**,
consistent instead with `intent.suggest_match` / `career.suggest_trajectory_
match` / `peer.suggest_peer`'s shared "never a zero-score result" rule (three
of this tier's four prior matchers, vs. `discover_events`'s one). R-020's own
zero-score inclusion was justified because LOCALITY ALONE (independent of any
topic signal) is a complete, honest basis for "this event is near me" —
opportunity matching has no equivalent second, independent inclusion axis:
skill overlap is the ENTIRE basis of a match, so a subject with no overlapping
skills has, honestly, no relationship to a given posting to report, exactly
as a zero-overlap intent pair has none.

Rejected: C2 (mirror `discover_events`'s zero-score-included rule — always
return a result, ranked by score). Would make "matching" indistinguishable
from "listing every posting that exists," which is not what "skill-based
matching" means when skill overlap is the only signal this module has.
Rejected: C3 (weight partial coverage, e.g. score by fraction of required
skills met rather than a raw count). Adds an arbitrary normalization decision
with no disclosed product rationale — every prior tag-overlap scorer in this
tier (`intent.py`, `event_discovery.py`) reports a raw overlap count, not a
fraction, and this module reproduces that rather than inventing a new metric.

### Fork D — self-match, cross-tenant, and employment-type filtering: **D1 (no self-match on the poster; cross-tenant allowed; `employment_types` is an optional pre-scoring filter on `rank_opportunities`)**

A subject who posted an opportunity cannot match their own posting
(`suggest_opportunity_match` returns `None` when `subject_profile.user_id ==
opportunity.posted_by_user_id`), mirroring every other `suggest_*` function's
"no self-match" rule. Cross-tenant pairs ARE matched — reproducing ADR-0016
Fork B's reasoning unchanged: a freelance/full-time opportunity is
definitionally open to candidates outside the posting tenant, the same as
B2C professional-networking matching generally.

`rank_opportunities` accepts an optional `employment_types` filter (restricting
the pool to `FREELANCE` and/or `FULL_TIME` postings BEFORE scoring, not after)
— the roadmap's task title names both kinds explicitly ("freelance +
full-time"), and a subject who wants freelance work only should not pay the
scoring cost of, or see, full-time postings mixed in. `EmploymentType` is a
closed, two-value `StrEnum` kept local to this module (mirrors `career.py`'s
own module-scoped `OptimizationGap`) rather than added to the shared
`enums.py`, which that file's own docstring reserves for R-001-wire-
reconciled enums plus `OrgRole` — this is a new, additive, pure-domain concept
with no wire contract yet.

Rejected: D2 (no employment-type filtering at all — a caller filters the
returned list itself). Would force every caller to pay the full scoring cost
of postings it already knows it does not want, for no benefit — filtering
before scoring is strictly better and costs nothing extra to implement.
Rejected: D3 (a single combined "opportunity kind" enum with more than two
values, e.g. anticipating "contract" or "internship"). No disclosed
requirement beyond the roadmap's own explicit two, named kinds; adding
unrequested values here would be inventing scope this task was not asked for.

### Fork E — bounds and determinism: **E1 (reuse `MAX_CANDIDATES=500`/`MAX_SUGGESTIONS=50`/`DEFAULT_MATCH_LIMIT=10`/`MAX_SKILLS=16`; rank by `(-score, opportunity_id)`)**

Candidate/result bounds and the per-field tag cap reuse this tier's
established magnitudes (`intent.py`'s `MAX_TAGS`/`MAX_CANDIDATES`/
`MAX_SUGGESTIONS`) for the same DoS/cost-guard reasoning, not loosened or
tightened without a disclosed justification — mirrors ADR-0020 Fork E's
identical rejection of raising bounds "because this entity is different."
Results rank by `(-score, opportunity_id)` — highest skill-overlap first,
with `opportunity_id` as a stable tie-break — mirroring `intent.rank_matches`'s
own `(-score, candidate_user_id)` tie-break rather than `event_discovery`'s
additional `starts_at` term: an `Opportunity` has no "soonest" dimension
analogous to an event session's start time, so a two-part key is sufficient
and consistent with the majority of this tier's own ranking functions.

Rejected: E2 (add `posted_at` as a secondary tie-break, ranking newer postings
first). A plausible real feature (recency-biased ranking) but not something
the roadmap asks for, and it would be the first ranking function in this
tier to use posting time as a signal rather than a mere validity field —
introducing it here without a disclosed requirement would be scope invention.

## What is deliberately NOT built here (named, not silently skipped)

- **No job board / listings marketplace / application workflow.** See Fork A.
  A future task (not yet named on the roadmap) owns the real product surface.
- **No resume/bio-text parsing.** Skills are caller-supplied opaque tags on
  both sides (`IntentProfile.offering`, `Opportunity.required_skills`) —
  identical posture to every tag-based module in this tier.
- **No modification of `intent.py` or `profile.py`.** `Opportunity` is
  additive — see Fork B.
- **No persistence for `Opportunity`.** No new store, no new Alembic
  migration. A follow-up task owns wiring `Opportunity` to a real table.
- **No REST/wire surface, no frontend.** Nothing in `contracts/openapi.yaml`
  changes, no frontend package is added.
- **No candidate-pool sourcing.** `rank_opportunities` ranks a
  CALLER-SUPPLIED pool; it does not query, crawl, or page through real
  postings — R-024 (Discovery feed) remains the natural future owner of
  candidate-pool sourcing for this and every other ranking function in this
  tier.

## Consequences

- A genuinely useful, genuinely tested skill-overlap matching CORE exists for
  a future listings/persistence/REST/UI/sourcing task to build the actual
  "opportunity matching" experience on top of, with the hard design questions
  (where required skills live, set-intersection vs. directional scoring,
  zero-score inclusion vs. exclusion, employment-type filtering, bounds,
  determinism) already resolved and covered by
  `tests/domain/test_opportunity.py`.
- No new attack surface is introduced: no new network endpoint, no new table,
  no new migration, no RLS change, and `intent.py`/`profile.py` are both
  untouched. The security review for this task is scoped accordingly — pure
  computation over caller-supplied domain objects, with no I/O.
- The roadmap's R-021 checklist line is intentionally NOT marked "the full
  10-16h skill-based opportunity-matching vision shipped" — it is marked
  shipped as THIS scoped skill-overlap seam, exactly as
  R-012/R-016/R-017/R-018/R-019/R-020 were, with the deferred listings/
  persistence/REST/UI/sourcing halves named above as the obvious next slices.
