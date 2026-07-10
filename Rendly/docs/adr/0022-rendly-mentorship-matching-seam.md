# ADR-0022 — Mentorship: an Exact-Tech-Stack-Proficiency Matching Seam (R-022)

Status: Accepted
Date: 2026-07-10
Builds on: ADR-0016/0017/0018/0020/0021 (the established scope-down discipline
for pure-domain, deterministic, no-persistence, no-REST/UI seams in this later
tier), ADR-0017 (`career.py`'s directional, asymmetry-driven mentor/mentee
labeling this module's shared-tag direction mirrors, generalized from a single
current/target stage to per-tag proficiency levels).

## Context

The roadmap names R-022 "Mentorship matching by exact tech-stack proficiency
🏦 POST-INVESTMENT", the seventh task of Rendly's Phase 3 "B2C professional
networking (VISION)" tier. As with R-016 through R-021, the roadmap gives no
further detail beyond the title.

Two things bound this task before any design choice is made:

1. **"Tech-stack proficiency" has no existing data source in this codebase.**
   R-016's `IntentProfile.offering`/`seeking` are bare tag SETS — a tag is
   either present or absent, with no notion of "how well." R-017's
   `CareerGoal` models a single current/target STAGE, not a per-technology
   skill level. Neither shape can express "proficient in `react` at
   `advanced` level" — this task's title is unambiguously about a level PER
   tag, which is a genuinely new piece of domain, not a reuse opportunity (the
   opposite conclusion from ADR-0021's Fork A, where "skill-based" reused
   `IntentProfile.offering` directly because a bare tag was sufficient there).
2. **"Mentorship" is inherently directional and asymmetry-driven**, exactly
   as ADR-0017 (R-017's career-trajectory matching) already established for
   career stages: a mentor/mentee pairing exists because two parties differ
   in some ordered measure, not because they share an identical value. R-022
   applies that same asymmetry-driven shape to a NEW measure (per-tag
   proficiency) instead of R-017's single career stage.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic scorer over a NEW `MentorshipProfile` opt-in type — a caller-supplied mapping of tech-stack tag to a closed, ordered `ProficiencyLevel`; no REST endpoint, no persistence, no mentorship session/scheduling workflow, no ML)**

`src/rendly/mentorship.py` adds `ProficiencyLevel` (closed, ORDERED — see Fork
B), `TechStackProficiency` (one tag/level pair), `MentorshipProfile` (the
opt-in record, one level per tag) + `bind_mentorship_profile`, and
`suggest_mentorship_match` / `rank_mentorship_matches` (the scorer). This
mirrors `intent.py`/`career.py`'s shape (an opt-in record identified by
`user_id`/`tenant_id`, not a separately-posted entity like `opportunity.py`'s
`Opportunity`) because a `MentorshipProfile` describes a PERSON's own
proficiency, not a listing someone else can apply to.

Rejected: A2 (an ML/embedding-based skill-inference model, e.g. inferring
proficiency from activity history). Same rejection ADR-0012/0016/0017/0018/
0020/0021 already made for their own A2 forks: no existing inference seam, no
training data, no honestly-bounded way to ship it in one task. Rejected: A3
(reuse `IntentProfile.offering` as the tag source, attaching levels
out-of-band). Would require overloading a field this codebase already ships
with a different, narrower meaning ("I can offer this," no level) — see
Context point 1; a `MentorshipProfile` with its own tag+level pairs is a
cleaner fit than bolting levels onto an unrelated record. Rejected: A4 (build
a mentorship request/accept/session workflow — persistence, the REST
endpoint, scheduling — in this task). A second, independent unit of work
exactly as every prior ADR in this tier's identical A4-shaped rejection
describes; the scorer is fully useful and fully testable alone.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
DETERMINISTIC scorer over two caller-supplied `MentorshipProfile` records — no
model, no activity-history inference, no generated match explanations beyond
the matched-tag lists themselves. "Mentorship matching by exact tech-stack
proficiency" in the roadmap's task name is exactly this scorer; the
request/accept/scheduling workflow the phrase might otherwise imply is not
built here.

### Fork B — proficiency scale: **B1 (`ProficiencyLevel` is a closed, ORDERED four-value enum — `beginner` < `intermediate` < `advanced` < `expert` — backed by an explicit rank mapping, not enum declaration order)**

Comparison (Fork C) requires an ordering; a closed enum with an explicit
`_LEVEL_RANK` mapping means the ordering can never silently change if the
enum's members are ever reordered or extended, and a caller can never supply
an arbitrary, incomparable proficiency string.

Rejected: B2 (an open string field for proficiency, e.g. free text). Cannot be
ordered without an implicit, undisclosed ranking rule — the same category of
under-specification this tier's ADRs consistently reject (mirrors why
`intent.py`'s tags are opaque SETS with no comparison, while this module's
levels must be a closed, ordered vocabulary to support Fork C at all).
Rejected: B3 (a numeric 1-10 proficiency score). More granular than "exact
tech-stack proficiency" discloses any need for, and invites bikeshedding over
what separates a 6 from a 7 with no product input; four named, ordered levels
is the minimal vocabulary that still supports a meaningful mentor/mentee
direction.

### Fork C — matching semantics: **C1 (EXACT-tag intersection + level-asymmetry direction: a shared tag contributes a direction only when the two levels differ; equal levels on a shared tag contribute nothing)**

This is the module's namesake boundary — "exact tech-stack proficiency" reads
as two conjoined requirements, both enforced literally: the tag must match
EXACTLY (no related-technology expansion, e.g. `react` never matches `vue`),
and the PROFICIENCY must differ for a direction to exist (two `expert`-level
peers on the same tag are not a mentor/mentee pair — mirrors `career.py`'s
`suggest_trajectory_match`, where a `TrajectoryMatch` is never constructed for
a 0 score). `candidate_mentors_on` names the tags where the candidate
outranks the subject; `candidate_mentees_on` names the tags where the subject
outranks the candidate — both directions can hold at once (mutual mentorship
across different stacks), exactly as `career.py`'s `candidate_is_mentor`/
`candidate_is_mentee` booleans can both be true.

Rejected: C2 (a fuzzy/related-technology expansion, e.g. treating `react` and
`vue` as partially overlapping). A real, larger feature (a technology
similarity graph) with no disclosed scope in the roadmap's task name; "exact"
unambiguously rules this out. Rejected: C3 (also counting equal-level shared
tags as a match, e.g. "peer" connections). `culture.py`'s symmetric
tag-intersection model already exists for peer/shared-interest connections;
duplicating that here under a "mentorship" name would blur what this module's
score means — a `MentorshipMatch` should mean "an asymmetry exists," full
stop.

### Fork D — tenant scope: **D1 (cross-tenant matching is explicitly ALLOWED — no tenant check at all)**

Reproduces ADR-0016/0017/0018/0020/0021's identical reasoning: B2C tech-stack
mentorship is definitionally cross-company — a subject in tenant A must be
able to match against a candidate in tenant B. `suggest_mentorship_match` /
`rank_mentorship_matches` do not inspect tenant at all.

## What is deliberately NOT built here (named, not silently skipped)

- **No activity-history or ML-inferred proficiency.** See Fork A's rejection
  of A2 — every level is caller-asserted, never inferred.
- **No persistence.** `MentorshipProfile` records are not stored; a caller
  supplies them each time, exactly as `intent.IntentProfile`/`career.CareerGoal`
  do before their own persistence follow-ups.
- **No REST/wire surface, no UI.** Nothing in `contracts/openapi.yaml`
  changes.
- **No mentorship request/accept/session workflow.** No scheduling, no
  "who initiated," no acceptance state machine — this module only scores a
  caller-supplied pair of profiles, it does not model how a mentorship
  relationship begins or is conducted.
- **No fuzzy/related-technology matching.** See Fork C's rejection of C2.
- **No peer/equal-level connections.** See Fork C's rejection of C3 —
  `culture.py` already owns that shape.

## Consequences

- A genuinely useful, genuinely tested mentorship-matching scorer exists for
  a future persistence/REST/scheduling task to build on, with the hard design
  questions (new opt-in type vs. reuse, proficiency vocabulary, exact-tag +
  asymmetry-only matching, cross-tenant scope) already resolved and covered
  by `tests/domain/test_mentorship.py`.
- No new attack surface is introduced: no new network endpoint, no new table,
  no new migration, no RLS change. The security review for this task is
  scoped accordingly — pure computation over caller-supplied domain objects,
  with no I/O.
- The roadmap's R-022 checklist line is intentionally NOT marked "the full
  10-16h mentorship-matching vision shipped" — it is marked shipped as THIS
  scoped matching seam, exactly as R-012/R-016/R-017/R-018/R-020/R-021 were,
  with the deferred request/accept/scheduling/persistence/REST halves named
  above as the obvious next slices.
