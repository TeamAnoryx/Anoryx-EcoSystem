# ADR-0023 — Consumer Onboarding: an Ordered Progression Seam Over the Existing Optimization Checklist (R-023)

Status: Accepted
Date: 2026-07-10
Builds on: ADR-0016 (the opt-in-record idiom, placeholder-actor-model
precedent), ADR-0017 (`career.optimization_gaps`, the checklist this ADR
composes over), ADR-0018 (`peer.py`'s composition-over-duplication
discipline, the template this ADR follows), ADR-0021/ADR-0022 (reuse-vs-
new-type forks this ADR reaches the same conclusion from).

## Context

The roadmap names R-023 "Consumer onboarding 🏦 POST-INVESTMENT", the eighth
task of Rendly's Phase 3 "B2C professional networking (VISION)" tier. Every
prior seam in this tier — `intent.py` (R-016), `career.py` (R-017),
`peer.py` (R-018), `privacy.py` (R-019), `event_discovery.py` (R-020),
`opportunity.py` (R-021), `mentorship.py` (R-022) — named this exact task,
in its own module docstring, as the owner of "real B2C consumer
identity/onboarding (R-023, still unshipped)": the thing none of them
built, because none of them was licensed to build it. This ADR is R-023
itself, and faces the same fork every predecessor already resolved for its
own scope: ship the full, disclosed-limitation vision, or ship a scoped
seam consistent with this tier's established discipline.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic ORDERED progression layer over R-017's existing `optimization_gaps` checklist; no new B2C identity/signup/auth model, no persistence, no REST, no UI)**

`src/rendly/onboarding.py` adds `ONBOARDING_STEP_ORDER` (an explicit order
over the existing `career.OptimizationGap` enum — see Fork B) and
`onboarding_status` (the resolver: which steps are done, which is next,
whether onboarding is complete). It takes the same `Profile` /
`IntentProfile` / `CareerGoal` inputs `optimization_gaps` already accepts.

Rejected: A2 (build the real B2C consumer identity/signup/auth model named
as this task's deferred work by every prior ADR in this tier). This is a
legitimately large, separate unit of work — its own persistence schema (a
consumer identity table set, distinct from R-004's enterprise identity
schema), its own RLS posture, its own auth flow, and its own REST surface
(none of which exist in `contracts/openapi.yaml` today) — not a same-shape
extension of an existing pure-compute module the way R-016→R-022 each were.
Attempting it inside one scoped task risks exactly the undisclosed,
unreviewed scope-widening banked rule 13 (referenced by ADR-0019 Fork C)
warns against; the honest move is the one R-016 already made for the
matching core it needed but didn't have (ADR-0016 §Rejected A3): ship the
smaller, fully-testable piece, and name the larger piece as the obvious
next slice. Rejected: A3 (ship nothing / a stub, treating R-023 as "just
onboarding UI copy"). The roadmap task is real, schedulable work — R-017's
checklist already computes WHAT is missing from a profile; nothing today
computes WHICH ONE TO ASK ABOUT NEXT, which is the actual "onboarding"
behavior (a linear flow, not a report) an unordered gap set cannot express
by itself. That gap is closed here, honestly scoped.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
deterministic ORDERING + "next step" layer over an already-shipped
checklist — no new opt-in type, no real identity/signup/auth model, no
generated onboarding copy. "Consumer onboarding" in the roadmap's task name
is exactly this ordered-progression resolver.

### Fork B — step order source: **B1 (an explicit `ONBOARDING_STEP_ORDER` tuple over the existing `OptimizationGap` enum, not a new parallel enum)**

`OptimizationGap` (R-017) already names the exact four facts a signup flow
would ask about (team, seeking tags, offering tags, career goal) as a
closed, four-value enum. Minting a second, structurally identical enum
(e.g. `OnboardingStep.SET_TEAM`) to relabel the same four checks would be
pure duplication with a translation layer between them — reuse is the
R-021 precedent (ADR-0021: "what I can offer already IS a skill
declaration — no new shape was needed"), and it applies unchanged here:
"what's missing from onboarding" already IS what `OptimizationGap` names.
`ONBOARDING_STEP_ORDER` supplies the one thing the enum itself does not: an
ORDER (mirrors `mentorship.py`'s `_LEVEL_RANK` — an explicit mapping rather
than relying on enum declaration order, ADR-0022 Fork B).

Rejected: B2 (a new `OnboardingStep` enum). Rejected for the duplication
reason above. Rejected: B3 (derive order from `OptimizationGap`'s
declaration order in `career.py`). Fragile — a future reordering of that
enum's source lines (e.g. alphabetizing) would silently change the
onboarding sequence with no visible signal, the identical fragility
`mentorship.py`'s ADR-0022 Fork B already rejected for proficiency ranking.

### Fork C — completion semantics: **C1 (`next_step` and `is_complete` are both derived from the SAME `optimization_gaps` call, never recomputed independently)**

`onboarding_status` calls `optimization_gaps` exactly once and partitions
`ONBOARDING_STEP_ORDER` by that single gap set — `completed_steps`,
`next_step`, `steps_completed`, and `is_complete` all read from that one
source, so none of them can disagree with each other or with the
underlying `ProfileOptimizationReport` (mirrors `MentorshipMatch`'s "score
can never disagree with its two levels" structural invariant, ADR-0022,
and `PeerSuggestion`'s "score is always the sum of its components"
invariant, ADR-0018).

Rejected: C2 (walk steps and short-circuit `optimization_gaps` itself
rather than computing the full report and filtering). Would require
reimplementing `career.py`'s four checks a second time instead of reusing
them — the same composition-over-duplication reasoning as Fork B, and it
buys nothing: `optimization_gaps` is O(1) (four fixed checks), so there is
no performance case for a hand-rolled short-circuit.

## What is deliberately NOT built here (named, not silently skipped)

- **No real B2C consumer identity/signup/auth model.** See Fork A. This
  module still operates over the existing enterprise `Profile` (R-002) as
  the placeholder actor model every prior B2C seam in this tier has used.
- **No persistence.** `OnboardingStatus` is computed fresh from
  caller-supplied `Profile`/`IntentProfile`/`CareerGoal` objects on every
  call, exactly as `optimization_gaps` itself does — no onboarding-progress
  record is stored.
- **No REST/wire surface, no UI/wizard component.** Nothing in
  `contracts/openapi.yaml` changes.
- **No new opt-in type.** See Fork B — this task reuses `OptimizationGap`
  rather than minting a parallel shape.
- **No discovery feed / premium features / creator-economy wiring**
  (R-024/R-025/R-026 remain their own, still-unshipped tasks).

## Consequences

- A genuinely useful ordered "what should this user do next" resolver
  exists for a future persistence/REST/UI task to build a real signup
  wizard on top of, with the hard design question (reuse the existing
  checklist vs. invent a new one; how to keep order and completion
  structurally consistent with it) already resolved and covered by
  `tests/domain/test_onboarding.py`.
- The still-deferred real B2C consumer identity/signup/auth model remains
  the single largest piece of unbuilt B2C-tier scope; this ADR names it
  explicitly (Fork A) rather than letting it continue to be referenced only
  in passing by every OTHER module's own docstring, as it has been since
  ADR-0016.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change — pure computation over
  caller-supplied domain objects and one already-shipped function call, no
  I/O.
- The roadmap's R-023 checklist line is intentionally NOT marked "the full
  real B2C identity/signup/onboarding vision shipped" — it is marked
  shipped as THIS scoped ordering seam, exactly as
  R-012/R-016/R-017/R-018/R-020/R-021/R-022 were, with the deferred
  real-identity/persistence/REST/UI halves named above as the obvious next
  slice.
