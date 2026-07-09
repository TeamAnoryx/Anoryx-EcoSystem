# ADR-0017 — Career: a Deterministic Profile-Optimization Checklist +
Trajectory-Stage Matching Seam (R-017)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0002 (R-002's `Profile` / `bind_profile` canonical-construction
idiom, and `OrgRole`'s FORK B = B1 org-membership-permission axis, distinct from
a career ladder), ADR-0012 (R-012's precedent for scoping a 🏦 POST-INVESTMENT
task down to a pure-domain, no-persistence, no-REST seam), ADR-0016 (R-016's
`IntentProfile` opt-in idiom, the cross-tenant-allowed Fork B reasoning this ADR
reproduces unchanged, and its own explicit naming of R-017 as one of the tasks
its matching CORE is meant to be reusable for).

## Context

The roadmap names R-017 "AI profile optimization + career-trajectory matching
🏦 POST-INVESTMENT", the second task of Rendly's Phase 3 "B2C professional
networking (VISION)" tier (grouped `R-016 -> R-026`, "Depends on: R-004/R-005 +
the matching core", "~10-16h each"). Unlike R-016 (which the roadmap and
ADR-0016 both singled out as "the matching core" the rest of the tier builds
on), R-017 has no further roadmap detail beyond its title — this ADR resolves
that title into a concrete, bounded scope the same way ADR-0016 did for R-016.

Two things bound this task before any design choice is made, mirroring
ADR-0016's own Context section:

1. **"AI profile optimization" cannot honestly mean AI here.** This codebase's
   established discipline (ADR-0012 §Decision, ADR-0016 §Decision, `culture.py`'s
   and `intent.py`'s own HONESTY BOUNDARY docstrings) is that a roadmap task name
   invoking "AI-powered" language ships as a deterministic, non-learned seam when
   there is no existing inference seam, no training data, and no disclosed way to
   keep an ML component honestly bounded within one task. That reasoning is
   unchanged for R-017: nothing in this codebase provides resume/bio-text
   embeddings or a profile-scoring model, and inventing one here would repeat the
   exact rejection ADR-0012 Fork A and ADR-0016 Fork A already made (there:
   "Rejected: A2 — an ML/embedding-based similarity or ranking model... deferred
   to whenever the funded vision actually specs it").
2. **"Career-trajectory matching" needs its own opt-in type, not a reuse of
   `IntentProfile`.** R-016's `IntentProfile` models arbitrary, plural
   `seeking`/`offering` skill TAGS (a set). A career trajectory is a single
   CURRENT/TARGET STAGE a person occupies at a point in time (e.g.
   `"senior_engineer" -> "staff_engineer"`) — overloading `IntentProfile` to also
   carry this would conflate two different shapes of opt-in data, and overloading
   `Profile.org_role` (a fixed, closed, org-membership-PERMISSION enum — FORK B
   of ADR-0002 — with only three values `admin`/`member`/`guest`) would be a
   category error: org-membership permission is not a career ladder.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic checklist + a deterministic directional stage-equality matcher; no REST endpoint, no persistence, no B2C identity model, no ML)**

`src/rendly/career.py` adds two independent pieces, both pure functions over
already-loaded domain objects, mirroring exactly how R-012 shipped `culture.py`
and R-016 shipped `intent.py` as pure-domain seams:

- `CareerGoal` (an explicit, per-user opt-in record: `user_id`, `tenant_id`,
  `current_stage`, `target_stage`, `opted_in_at`) + `bind_career_goal` (the
  canonical construction path, deriving ids from a real `Profile`) +
  `suggest_trajectory_match` / `rank_trajectory_matches` (directional
  stage-equality scoring — see Fork C).
- `optimization_gaps` (a fixed, four-check completeness function — see Fork E)
  that takes `Profile` plus optional `IntentProfile` (R-016) and `CareerGoal`
  (this module) and returns a `ProfileOptimizationReport`.

There is no new migration, no new table, no new REST route, and no
`policy.schema.json` touch — identical posture to ADR-0016 Fork A.

Rejected: A2 (an ML/embedding-based profile-quality or trajectory-similarity
model). Same rejection as ADR-0012/ADR-0016's own A2: no existing inference
seam, no training data, no honestly-bounded way to ship it in one task.
Rejected: A3 (build a real B2C identity/onboarding model in this task so
optimization/matching has "real" B2C users to run over). That remains R-023's
job, unchanged from ADR-0016's own A3 rejection. Rejected: A4 (build the REST
endpoint + persistence for `CareerGoal` in the same PR). A second, independent
unit of work (Alembic migration, an RLS/cross-tenant-eligibility decision
notably harder than R-004's same-tenant model, a wire-contract addition);
bundling it here risks shipping either half-finished, the same failure mode
ADR-0012/ADR-0016 both avoided identically. The compute-only seam is fully
useful and fully testable alone, so it ships alone (see Consequences for the
named follow-ups).

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is (a) a FIXED,
NAMED four-check completeness checklist (`optimization_gaps`) — no generated
text, no model, no learned scoring — and (b) a DETERMINISTIC directional
stage-EQUALITY scorer (`suggest_trajectory_match` / `rank_trajectory_matches`)
— no learned ranking, no fuzzy/semantic stage matching (two stage labels match
only on exact string equality; `"staff_engineer"` and `"Staff Engineer"` do
NOT match). "AI profile optimization" in the roadmap's task name is exactly the
fixed checklist that ships; the "AI" language describes the eventual vision
this checklist is a scoped-down placeholder for, not something this task
builds — the same disclosure pattern as `culture.py`'s and `intent.py`'s own
boundaries.

### Fork B — tenant scope (trajectory matching): **B1 (cross-tenant matching is explicitly ALLOWED — no tenant check at all)**

Reproduces ADR-0016 Fork B's reasoning unchanged: `culture.suggest_connection`
(R-012) refuses cross-tenant pairs because internal cross-department matching
within one company must never leak across companies; R-016 and this task are
the opposite case — professional/career mentorship that does not cross company
lines is not "B2C", it is just `culture.py` again. `suggest_trajectory_match` /
`rank_trajectory_matches` therefore do not inspect tenant at all (both tenant
ids are carried through onto the returned `TrajectoryMatch` so a caller can see
them, exactly as `IntentMatch` does).

Rejected: B2/B3 — identical to ADR-0016's own rejections (reusing
`culture.py`'s refusal "for safety" would silently defeat the task; an
explicit per-tenant opt-in allow-list is a real future feature this task is
not positioned to decide un-asked).

**Disclosed limitation (reproduces ADR-0016's own):** this pure-compute seam
has no way to know, and does not attempt to decide, WHICH candidates a real
deployment should even be allowed to place in a subject's candidate pool. That
eligibility decision belongs to whatever future persistence/candidate-pool
loader supplies `rank_trajectory_matches`'s `candidates` argument.

### Fork C — matching semantics: **C1 (directional stage EQUALITY: `candidate.current_stage == subject.target_stage` OR `candidate.target_stage == subject.current_stage`)**

A career trajectory is a single position on a path, not a set of tags, so the
right primitive is not R-016's tag-SET intersection but a single-value equality
check evaluated in both directions: the candidate already occupies the stage
the subject is aiming for (`candidate_is_mentor`), or the candidate is aiming
for the stage the subject already occupies (`candidate_is_mentee`). Both may
hold at once (mutual, differently-directed mentorship potential between two
people each one stage apart in opposite directions) — `score` is the count of
directions that hold (1 or 2; never constructed at 0, mirroring
`IntentMatch`'s "never a zero-score match" rule).

Rejected: C2 (reuse `intent.suggest_match`'s tag-set intersection over a
`stages: tuple[str, ...]` field instead of a single `current_stage`/
`target_stage` pair). Would blur "the tags I hold" with "the single stage I
occupy right now" — a career stage is singular by definition (you are not
simultaneously "senior_engineer" AND "staff_engineer"), so modeling it as an
unbounded tag set would admit meaningless states this module cannot validate
against. Rejected: C3 (fuzzy/substring stage matching, e.g. normalize casing or
strip whitespace). Adds a real product surface (what normalization rules? what
about genuinely different labels for the same real-world stage, e.g.
`"L5"` vs `"senior_engineer"`?) with no disclosed benefit at this scope — stage
labels stay opaque, caller-defined strings and it is the CALLER's job to use a
consistent vocabulary, exactly as `intent.py` leaves tag semantics to its
caller.

### Fork D — scoring + determinism: **D1 (score = count of directions that hold; ties break on `candidate_user_id` ascending; hard-capped inputs; `current_stage != target_stage` enforced at construction)**

Mirrors `intent.py`'s `MAX_CANDIDATES`/`MAX_SUGGESTIONS` discipline exactly
(reused at the same magnitudes: `MAX_CANDIDATES = 500`, `MAX_SUGGESTIONS = 50`,
`DEFAULT_MATCH_LIMIT = 10`) and adds one new construction-time invariant
`intent.py` has no equivalent of: `CareerGoal` rejects `current_stage ==
target_stage` (a "goal" that restates the current stage is not a trajectory,
and would trivially always self-match as both mentor and mentee under Fork C).
`rank_trajectory_matches` sorts by `(-score, candidate_user_id)` so the SAME
input always produces the SAME output.

Rejected: D2 (weight `candidate_is_mentor` higher than `candidate_is_mentee`,
e.g. prioritize "who can help me" over "who I can help"). Adds an arbitrary
weighting decision with no disclosed product rationale, mirroring ADR-0016's
own D2 rejection for an analogous asymmetric-weighting proposal.

### Fork E — profile optimization: **E1 (a fixed, four-check deterministic checklist; no free-form advice)**

`optimization_gaps` evaluates exactly four NAMED, closed-enum checks, always in
the same order, over `Profile` (R-002, required) plus optional `IntentProfile`
(R-016) and `CareerGoal` (this module): `MISSING_TEAM` (`profile.team` unset),
`NO_SEEKING_TAGS` / `NO_OFFERING_TAGS` (the intent profile is absent or has no
tags in that field — R-016's matching core cannot surface this user without
at least one), `NO_CAREER_GOAL` (this module's own trajectory matching cannot
run for this user without one). `completeness_score` is always derived as
`TOTAL_OPTIMIZATION_CHECKS - len(gaps)`, never computed independently, so the
two can never disagree. Returning a closed `OptimizationGap` `StrEnum` (rather
than a free-form string or a natural-language sentence) structurally enforces
this module's own "no generated text" boundary — nothing in the type system
allows a caller to receive anything other than one of the four fixed values.

Rejected: E2 (generate a natural-language "advice" string per gap, e.g. "Add a
team to improve your profile"). This is exactly the "AI-powered" framing this
task's HONESTY BOUNDARY (Fork A) forecloses — a template string dressed as
generated advice is still not what "AI profile optimization" implies, and a
genuinely useful copy layer belongs at a UI/presentation layer that can choose
its own wording per gap code, not baked into the domain seam. Rejected: E3 (a
single scalar "profile health score" with no itemized gaps). Strictly less
useful than the itemized list this ships (a caller can always sum the list to
get a scalar; the reverse is not true), and would hide exactly which of the
four checks failed.

## What is deliberately NOT built here (named, not silently skipped)

- **No real B2C consumer identity.** Both `CareerGoal` and `optimization_gaps`
  operate over the existing enterprise `Profile` (R-002) as a placeholder actor
  model — identical posture to `intent.py`, R-023 (Consumer onboarding) remains
  the natural owner of a real, non-tenant-scoped B2C identity.
- **No persistence.** `CareerGoal` records are not stored; a caller must supply
  them each time. A follow-up task owns a `rendly.career_goals` store (with the
  same cross-tenant RLS/eligibility question ADR-0016 Fork B disclosed) + an
  Alembic migration — naturally paired with R-016's own deferred
  `intent_profiles` store follow-up.
- **No REST/wire surface.** Nothing in `contracts/openapi.yaml` or
  `contracts/rendly-domain.schema.json` changes (mirrors `IntentProfile`, which
  is also absent from the domain schema — see `tests/domain/
  test_json_schema_contracts.py`, unchanged by this task). A follow-up task
  owns the contract addition and the FastAPI router wiring it to these pure
  functions.
- **No candidate-pool eligibility/discovery.** Identical to ADR-0016's own
  disclosed limitation — R-024 (Discovery feed) is the natural home for
  deciding which candidates a subject is even shown.
- **No stage-vocabulary normalization or a canonical career-ladder taxonomy.**
  See Fork C's rejection of C3 — stage labels stay opaque, caller-supplied
  strings.
- **No natural-language optimization advice.** See Fork E's rejection of E2 —
  only the four closed `OptimizationGap` codes are returned; any user-facing
  copy is a presentation-layer concern outside this seam.

## Consequences

- A genuinely useful, genuinely tested career-trajectory matching CORE and
  profile-completeness checklist exist for a future persistence/REST/identity
  task to build on (R-018 peer-networking UI, R-021 skill-based opportunity
  matching, R-022 mentorship matching by tech-stack are natural consumers of
  the trajectory matcher; any future UI is a natural consumer of
  `optimization_gaps`), with the hard design questions (single-stage vs.
  tag-set semantics, directionality, cross-tenant handling, DoS bounds, the
  "no generated text" boundary) already resolved and covered by
  `tests/domain/test_career.py`.
- No new attack surface is introduced: no new network endpoint, no new table,
  no new migration, no RLS change. The security review for this task is scoped
  accordingly — pure computation over caller-supplied domain objects, with no
  I/O, mirroring ADR-0016's own Consequences.
- The roadmap's R-017 checklist line is intentionally NOT marked "the full
  10-16h AI profile-optimization + career-matching vision shipped" — it is
  marked shipped as THIS scoped checklist + trajectory-matching seam, exactly
  as O-009/O-010/O-011/R-012/R-013/R-014/R-015/R-016 were, with the deferred
  identity/persistence/REST/discovery/copy halves named above as the obvious
  next slices.
