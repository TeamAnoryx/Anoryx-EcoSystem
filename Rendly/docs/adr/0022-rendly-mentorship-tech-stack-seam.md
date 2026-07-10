# ADR-0022 — Mentorship: an Exact-Stack, Ordered-Proficiency Matching Seam (R-022)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0016/ADR-0017/ADR-0021 (the established opt-in-record idiom
and reuse-vs-new-type discipline for this B2C tier), ADR-0021 in particular
for its explicit "when to reuse vs. when to add a new type" reasoning, which
this ADR reaches the opposite conclusion from for a principled reason (see
Context).

## Context

The roadmap names R-022 "Mentorship matching by exact tech-stack proficiency
🏦 POST-INVESTMENT", the seventh task of Rendly's Phase 3 "B2C professional
networking (VISION)" tier.

One thing bounds this task before any design choice is made: **does this
task need a NEW opt-in type, or does it reuse an existing one?** ADR-0021
(R-021) reused `intent.IntentProfile.offering` directly because "what I can
offer" already IS a skill declaration — no new shape was needed. R-022 is
different: neither existing opt-in type captures "ordered proficiency in a
specific named technology":

- `IntentProfile.offering`/`.seeking` are UNORDERED tag SETS — there is no
  notion of skill LEVEL, only presence/absence of a tag. A tag intersection
  cannot express "I am a beginner in React and you are an expert."
- `career.CareerGoal`'s `current_stage`/`target_stage` are CAREER-LADDER
  positions (e.g. "senior_engineer" → "staff_engineer"), not proficiency in
  a specific named technology, and a `CareerGoal` is singular per user (one
  trajectory), while a person can be proficient in many tech stacks at once.

This is a genuinely new shape, so — unlike R-021 — a new opt-in type is the
correct, minimal-not-excessive choice here, not scope creep.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic exact-stack + ordered-proficiency scorer; new `TechStackProficiency` opt-in type; no REST endpoint, no persistence, no ML)**

`src/rendly/mentorship.py` adds `ProficiencyLevel` (a closed, four-value,
EXPLICITLY-ORDERED enum — see Fork B), `TechStackProficiency` (one record
per user PER STACK — a user proficient in multiple stacks holds multiple
records) + `bind_tech_stack_proficiency`, and `suggest_mentorship_match` /
`rank_mentors` (the scorer).

Rejected: A2 (an ML/embedding-based skill-level inference model). Same
rejection every prior ADR in this tier has made for its own A2 fork: no
existing inference seam, no training data, no honestly-bounded way to ship
it in one task. Rejected: A3 (reuse `IntentProfile` by encoding level into
the tag string, e.g. `"react:expert"`). Would smuggle structured data into
an opaque tag field never designed for it, breaking `IntentProfile`'s own
"opaque, caller-defined tag" contract and making level comparison a string-
parsing problem instead of a real ordered-enum comparison — strictly worse
than a proper new type. Rejected: A4 (build a mentorship-session booking/
scheduling workflow in this task). A second, independent unit of work — the
scorer is fully useful and fully testable alone; R-007's huddles already
exist as the actual 1-on-1 mechanism a future task could wire this seam's
output to.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
DETERMINISTIC, exact-stack-match, ordered-proficiency-gap scorer — no model,
no fuzzy stack-name resolution (`"React"` and `"react"` do not match), no
generated mentorship advice. "Mentorship matching by exact tech-stack
proficiency" in the roadmap's task name is exactly this scorer.

### Fork B — proficiency ordering: **B1 (an explicit `_LEVEL_RANK` mapping, not enum declaration order)**

`ProficiencyLevel` is a `StrEnum` (for wire-serialization consistency with
every other enum in this codebase — `model_dump(mode="json")` matches the
plain string), but `StrEnum` has no inherent ordering `int`/`IntEnum` would
provide. Rather than rely on declaration order (fragile — a future edit
reordering the enum's source lines would silently change matching
semantics with no visible signal), the ordering is a separate, explicit
`_LEVEL_RANK: dict[ProficiencyLevel, int]` constant.

Rejected: B2 (make `ProficiencyLevel` an `IntEnum` instead, so `<`/`>`
work natively). Would diverge from every other closed-vocabulary field in
this codebase's convention (`OrgRole`, `ChannelRole`, `PresenceStatus`,
`OpportunityKind`, `PrivacyField` are all `StrEnum`), and `model_dump(mode=
"json")` on an `IntEnum` member serializes to its representative form
inconsistently with the rest of the domain's plain-string wire discipline.

### Fork C — matching semantics: **C1 (mentor's rank must be STRICTLY greater than mentee's rank on the SAME stack; score = rank gap)**

A peer at the same proficiency level is not a mentor — mentorship is
definitionally asymmetric. `suggest_mentorship_match` requires both an
exact `stack` match AND `_LEVEL_RANK[mentor] > _LEVEL_RANK[mentee]`; the
`score` is the gap itself (1..3), reported directly rather than a derived
bucket, so a caller can distinguish "one level up" from "beginner-to-
expert" without recomputing it from the two levels the match already
carries.

Rejected: C2 (allow a same-or-lower-level "peer study buddy" match as a
lower-scored fallback). A real, different feature ("peer matching") this
task's name does not ask for — "mentorship" implies directionality;
inventing a peer-matching mode here would be undisclosed scope-widening.

### Fork D — tenant scope: **D1 (cross-tenant matching is explicitly ALLOWED — no tenant check at all)**

Reproduces every prior B2C-tier ADR's identical reasoning: professional
mentorship across companies is definitionally cross-tenant.
`suggest_mentorship_match` / `rank_mentors` do not inspect tenant at all.

## What is deliberately NOT built here (named, not silently skipped)

- **No fuzzy/normalized stack matching.** See Fork A's HONESTY BOUNDARY —
  exact string equality only.
- **No persistence.** `TechStackProficiency` records are not stored; a
  caller supplies them each time, exactly as `IntentProfile`/`CareerGoal`
  do before their own persistence follow-ups.
- **No REST/wire surface, no UI.** Nothing in `contracts/openapi.yaml`
  changes.
- **No mentorship-session booking/scheduling.** A future task owns wiring
  this scorer's output to R-007's existing 1-on-1 huddle mechanism.
- **No "peer" (same-level) matching mode.** See Fork C's rejection of C2.

## Consequences

- A genuinely useful, genuinely tested exact-stack, ordered-proficiency
  matching scorer exists for a future persistence/REST/booking task to
  build on, with the hard design questions (new type vs. reuse, explicit
  ordering, directional-only matching, cross-tenant scope) already resolved
  and covered by `tests/domain/test_mentorship.py`.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change. The security review for this
  task is scoped accordingly — pure computation over caller-supplied
  domain objects, with no I/O.
- The roadmap's R-022 checklist line is intentionally NOT marked "the full
  10-16h mentorship-matching vision shipped" — it is marked shipped as
  THIS scoped matching seam, exactly as
  R-012/R-016/R-017/R-018/R-020/R-021 were, with the deferred persistence/
  REST/booking halves named above as the obvious next slices.
