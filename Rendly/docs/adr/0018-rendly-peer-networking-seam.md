# ADR-0018 — Peer: a Deterministic Composition Seam over the Intent (R-016) and
Career-Trajectory (R-017) Matching Cores (R-018)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0016 (R-016's `IntentProfile`/`IntentMatch`/`rank_matches` — the
"matching core" the whole B2C tier is declared to build on, and the Fork A/B
scope-down discipline this ADR reproduces unchanged), ADR-0017 (R-017's
`CareerGoal`/`TrajectoryMatch`/`rank_trajectory_matches`, and its own
Consequences section, which explicitly names "R-018 peer-networking UI" as a
"natural consumer of the trajectory matcher" — this ADR is that consumption,
scoped down the same way ADR-0017 scoped down its own "AI" framing).

## Context

The roadmap names R-018 "Hyper-personalized peer-networking interface 🏦
POST-INVESTMENT", the third task of Rendly's Phase 3 "B2C professional
networking (VISION)" tier (`R-016 -> R-026`, "Depends on: R-004/R-005 + the
matching core", "~10-16h each"). Like R-017, R-018 has no further roadmap
detail beyond its title — this ADR resolves that title the same way ADR-0016
resolved R-016's and ADR-0017 resolved R-017's.

Two things bound this task before any design choice is made, mirroring both
prior ADRs' own Context sections:

1. **"Hyper-personalized" cannot honestly mean personalized-by-a-model here.**
   This codebase's established discipline (ADR-0012 §Decision, ADR-0016
   §Decision, ADR-0017 §Decision, and `culture.py`/`intent.py`/`career.py`'s
   own HONESTY BOUNDARY docstrings) is that a roadmap task name invoking
   "hyper-personalized"/"AI-powered" language ships as a deterministic,
   non-learned seam when there is no existing inference seam, no training
   data, and no disclosed way to keep an ML component honestly bounded within
   one task. Nothing in this codebase provides a personalization/ranking
   model, and inventing one here would repeat the exact rejection
   ADR-0012/0016/0017's own Fork A already made.
2. **"Interface" cannot honestly mean a UI or REST surface here.** Every prior
   task in this tier (R-012, R-016, R-017) shipped as a pure-domain,
   no-persistence, no-REST seam and explicitly deferred the wire/UI layer to a
   named follow-up — Rendly has no frontend package at all (unlike Sentinel's
   `frontend/`), and R-018 has no persistence-backed identity store to build a
   real interface against (R-016's `intent_profiles` store and R-017's
   `career_goals` store are both still-deferred follow-ups, per their own
   ADRs' "What is deliberately NOT built here" sections). Building a REST
   endpoint or UI in this task would mean inventing that persistence layer
   un-asked, the same A4/A3-shaped scope creep ADR-0016 and ADR-0017 both
   already rejected for themselves. This run is unattended (no human
   available to resolve the resulting ambiguity mid-run), so the conservative
   reading is the one consistent with every seam this tier has shipped so
   far: "interface" describes the eventual vision layer, not something this
   task builds.

R-018's own differentiator from R-016/R-017 is not a new signal — it is
**composition**: ADR-0017's Consequences section names R-018 as a "natural
consumer" of the trajectory matcher, and the roadmap groups R-016 -> R-026
under one shared "the matching core" dependency. The one genuinely new thing
R-018 can honestly ship, without inventing a model or a wire surface, is a
seam that COMBINES the two already-shipped signals (complementary intent tags
+ career-trajectory stage) into a single ranked suggestion — "hyper" read
honestly as "using every signal a person has opted into," not as a learned
personalization model.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic composition of `intent.suggest_match` + `career.suggest_trajectory_match`; no REST endpoint, no persistence, no UI, no ML)**

`src/rendly/peer.py` adds one new piece, mirroring exactly how R-012/R-016/R-017
shipped `culture.py`/`intent.py`/`career.py` as pure-domain seams:

- `PeerSuggestion` (an immutable composite result carrying the component
  `IntentMatch | None` and `TrajectoryMatch | None`, plus a combined `score`) +
  `suggest_peer` / `rank_peers` (composition scoring — see Fork C).

There is no new opt-in type: `suggest_peer` takes the SAME `IntentProfile`
(R-016) and `CareerGoal` (R-017) opt-in objects the existing modules already
define, as independent OPTIONAL arguments per side (see Fork B). There is no
new migration, no new table, no new REST route, and no `policy.schema.json`
touch — identical posture to ADR-0016/ADR-0017 Fork A.

Rejected: A2 (an ML/embedding-based personalization or ranking model). Same
rejection as ADR-0012/0016/0017's own A2: no existing inference seam, no
training data, no honestly-bounded way to ship it in one task. Rejected: A3
(build the REST endpoint + a "peer suggestions" persistence/cache layer in the
same PR). A second, independent unit of work exactly as ADR-0016/0017's own
A4 rejections describe — the compute-only composition seam is fully useful
and fully testable alone. Rejected: A4 (build a real frontend "interface" —
a page/component rendering suggestions). Rendly has no frontend package to
extend, and inventing one here — with no backend REST surface to call — would
ship an unconnected UI shell, the same half-finished-implementation failure
mode the ecosystem's engineering standards explicitly forbid.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
DETERMINISTIC combination of two already-deterministic component scorers — no
generated text, no model, no learned weighting, no new personalization signal
beyond what R-016/R-017 already opted a user into. "Hyper-personalized
peer-networking interface" in the roadmap's task name is exactly this
composition seam; the "hyper-personalized"/"interface" language describes the
eventual vision this seam is a scoped-down placeholder for, not something this
task builds — the same disclosure pattern as `culture.py`/`intent.py`/
`career.py`'s own boundaries.

### Fork B — signal participation: **B1 (each of the two component signals is independently optional on EACH side; a suggestion requires at least one component match, not both)**

A real user may have opted into `intent.IntentProfile`, `career.CareerGoal`,
both, or neither (per-user, independent opt-ins — see each module's own
"PRIVACY-CONTROLLED, by construction" section). Requiring BOTH signals from
BOTH sides before a peer suggestion could ever exist would silently exclude
every user who opted into only one signal, which is not "hyper-personalized",
it is "under-covered." `suggest_peer` therefore takes
`subject_intent`/`candidate_intent`/`subject_goal`/`candidate_goal` as four
independent `| None` arguments: the intent component is computed only when
BOTH sides supply an `IntentProfile` (mirrors `intent.suggest_match`'s own
required-pair signature — a match cannot be computed from one side alone);
same for the trajectory component. A `PeerSuggestion` is returned only when at
least one component is non-`None` (never an all-`None`, zero-signal result) —
mirrors `IntentMatch`/`TrajectoryMatch`'s own "never a zero-score match" rule
one level up.

Rejected: B2 (require both signals on both sides). Discards every
single-signal user; strictly less useful, and the roadmap's grouping of
R-016 -> R-026 under one shared "matching core" implies these signals are
meant to compose additively, not exclusively. Rejected: B3 (silently treat a
missing opt-in as an automatic non-match for the WHOLE suggestion, i.e. skip
the pair entirely if either signal is absent on either side). Same defect as
B2 phrased differently — it would make one missing opt-in poison an otherwise
valid single-signal match.

### Fork C — combined scoring: **C1 (score = sum of whichever component scores were computed; ties break on `candidate_user_id` ascending)**

Mirrors `career.py`'s own Fork D reasoning: the combined `score` is not an
independently-computed value, it is `(intent_match.score if intent_match else
0) + (trajectory_match.score if trajectory_match else 0)` — deriving it this
way (rather than inventing a separate weighted formula) means the composite
can never disagree with its two components, and a caller can always recover
"why" a suggestion scored the way it did from the two component objects
`PeerSuggestion` carries. `rank_peers` sorts by `(-score, candidate_user_id)`
so the SAME input always produces the SAME output — mirrors
`rank_matches`/`rank_trajectory_matches` exactly.

Rejected: C2 (weight the intent component higher than the trajectory
component, or vice versa). Adds an arbitrary weighting decision with no
disclosed product rationale — mirrors ADR-0016 Fork D's and ADR-0017 Fork D's
own rejections of analogous asymmetric-weighting proposals. Rejected: C3
(normalize the two component scores onto a common 0-1 scale before summing,
e.g. because `IntentMatch.score` and `TrajectoryMatch.score` have different
natural ranges). `IntentMatch.score` is unbounded by tag-set size (up to
`2 * MAX_TAGS`) while `TrajectoryMatch.score` is capped at 2 by construction
(Fork C of ADR-0017) — introducing a normalization formula here is a real
product/statistics decision (what's the right divisor? does it change as
`MAX_TAGS` changes?) with no disclosed benefit at this scope; a caller that
wants normalized ranking can already do so from the two raw component scores
`PeerSuggestion` exposes.

### Fork D — tenant scope: **D1 (cross-tenant peer suggestions are explicitly ALLOWED — no tenant check at all)**

Reproduces ADR-0016 Fork B's and ADR-0017 Fork B's reasoning unchanged: both
component matchers this seam composes already allow cross-tenant pairs
(B2C professional networking is definitionally cross-company), so a
composition of the two must not silently introduce a same-tenant restriction
neither component has. `suggest_peer` / `rank_peers` do not inspect tenant at
all; both tenant ids are carried through onto the returned `PeerSuggestion`
(via its component matches), exactly as `IntentMatch`/`TrajectoryMatch` do.

Rejected: D2/D3 — identical to ADR-0016's and ADR-0017's own rejections
(reusing `culture.py`'s refusal "for safety" would silently defeat both
composed signals; an explicit per-tenant opt-in allow-list is a real future
feature this task is not positioned to decide un-asked).

### Fork E — bounds + determinism: **E1 (reuse `MAX_CANDIDATES=500`/`MAX_SUGGESTIONS=50`/`DEFAULT_MATCH_LIMIT=10` at the same magnitudes; no de-duplication)**

Mirrors `intent.py`'s and `career.py`'s own DoS/cost-guard discipline exactly
— this seam's per-candidate cost is strictly higher than either component
alone (it may compute both), so reusing rather than loosening the existing
bounds is the conservative choice. `rank_peers` does not de-duplicate
`candidates` by `candidate_user_id` — a caller passing the same candidate
twice gets that candidate scored (and possibly listed) twice, exactly as
`rank_matches`/`rank_trajectory_matches` behave.

Rejected: E2 (raise the bounds because this seam is "more valuable" per
candidate). No disclosed justification for a different magnitude; the
existing bounds were sized as a DoS guard on the pairwise scorer, not a
product decision about result usefulness, and that reasoning does not change
just because a second scorer runs alongside the first.

## What is deliberately NOT built here (named, not silently skipped)

- **No real B2C consumer identity.** `suggest_peer` / `rank_peers` operate over
  the existing enterprise `Profile` (R-002) plus the existing `IntentProfile`
  (R-016) / `CareerGoal` (R-017) opt-in objects as a placeholder actor model —
  identical posture to `intent.py`/`career.py`. R-023 (Consumer onboarding)
  remains the natural owner of a real, non-tenant-scoped B2C identity.
- **No persistence.** No new store, no new Alembic migration. A follow-up task
  owns wiring this composition seam to R-016's and R-017's own already-named
  deferred `intent_profiles`/`career_goals` stores.
- **No REST/wire surface, no frontend.** Nothing in `contracts/openapi.yaml`
  or `contracts/rendly-domain.schema.json` changes, and no frontend package is
  added. A follow-up task owns the contract addition, the FastAPI router, and
  the actual "interface" (UI) the roadmap's task name names.
- **No candidate-pool eligibility/discovery.** Identical to ADR-0016's and
  ADR-0017's own disclosed limitation — R-024 (Discovery feed) is the natural
  home for deciding which candidates a subject is even shown.
- **No new personalization signal.** This task composes the two EXISTING
  signals; it does not add a third (e.g. shared interests via `culture.py`
  would be a same-tenant-only signal and cannot honestly compose with two
  cross-tenant-allowed signals without a new tenant-scope decision this task
  is not positioned to make un-asked).

## Consequences

- A genuinely useful, genuinely tested peer-suggestion composition CORE exists
  for a future persistence/REST/identity/UI task to build the actual
  "interface" on top of, with the hard design questions (signal-optionality,
  combined scoring, cross-tenant handling, DoS bounds) already resolved and
  covered by `tests/domain/test_peer.py`.
- No new attack surface is introduced: no new network endpoint, no new table,
  no new migration, no RLS change. The security review for this task is
  scoped accordingly — pure computation over caller-supplied domain objects,
  with no I/O, mirroring ADR-0016's/ADR-0017's own Consequences.
- The roadmap's R-018 checklist line is intentionally NOT marked "the full
  10-16h hyper-personalized peer-networking interface vision shipped" — it is
  marked shipped as THIS scoped composition seam, exactly as
  O-009/O-010/O-011/R-012/R-013/R-014/R-015/R-016/R-017 were, with the
  deferred identity/persistence/REST/UI/discovery halves named above as the
  obvious next slices.
