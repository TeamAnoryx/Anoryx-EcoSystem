# ADR-0021 — Opportunity: a Skill-Based Matching Seam over R-016's Offering Tags (R-021)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0016 (R-016's `IntentProfile.offering` — reused directly, not
reinvented), ADR-0017/ADR-0018/ADR-0020 (the established scope-down
discipline for pure-domain, deterministic, no-persistence, no-REST/UI seams
in this later tier), ADR-0013 (`event.py`'s `bind_*`/canonical-construction
pattern this module's `bind_opportunity` mirrors).

## Context

The roadmap names R-021 "Skill-based opportunity matching (freelance +
full-time) 🏦 POST-INVESTMENT", the sixth task of Rendly's Phase 3 "B2C
professional networking (VISION)" tier. As with R-017 through R-020, the
roadmap gives no further detail beyond the title.

Two things bound this task before any design choice is made:

1. **"Skill-based" matching already has a natural data source: R-016's
   `IntentProfile.offering`.** R-016 modeled "what a user can offer" as a
   tag set precisely to support exactly this kind of downstream consumer
   (ADR-0016's Consequences names R-017/R-018/R-021/R-022 as expected
   consumers of the matching core). Inventing a SECOND, parallel "my
   skills" opt-in type here would duplicate a concept this codebase already
   has, the same category of redundancy ADR-0017 avoided by choosing NOT to
   overload `IntentProfile` for career trajectory (a genuinely different
   shape) — but skill tags for a job ARE the same shape as "what I offer",
   so reuse here is the correct call, not a mismatch.
2. **"Opportunity matching" is fundamentally person-to-LISTING, not
   person-to-person.** Every prior seam in this tier (R-016, R-017, R-018)
   matches one `Profile` against another. R-021 needs a NEW kind of entity
   — a freelance/full-time role someone has posted — that this codebase has
   never modeled. This is the one genuinely new piece of domain this task
   introduces.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic set-intersection scorer between R-016's `IntentProfile.offering` and a NEW `Opportunity.required_skills`; no REST endpoint, no persistence, no applicant-tracking workflow, no ML)**

`src/rendly/opportunity.py` adds `Opportunity` (a single-poster freelance/
full-time listing, mirrors `event.Event`'s single-host construction idiom) +
`bind_opportunity`, `OpportunityKind` (a closed, informational enum — see
Fork B), and `suggest_opportunity_match` / `rank_opportunities` (the scorer).
Crucially, there is NO new "my skills" opt-in type — the subject side reuses
R-016's already-shipped `IntentProfile.offering` directly.

Rejected: A2 (an ML/embedding-based resume-to-job matching model). Same
rejection ADR-0012/0016/0017/0018/0020 already made for their own A2 forks:
no existing inference seam, no training data, no honestly-bounded way to
ship it in one task. Rejected: A3 (invent a parallel "my skills" opt-in
type instead of reusing `IntentProfile.offering`). Would duplicate an
existing concept for no disclosed benefit — see Context point 1. Rejected:
A4 (build an opportunity-posting workflow — approval, expiry, applicant
tracking, persistence, the REST endpoint — in this task). A second,
independent unit of work exactly as every prior ADR in this tier's
identical A4-shaped rejection describes; the scorer is fully useful and
fully testable alone.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
DETERMINISTIC set-intersection scorer between two caller-supplied tag sets
— no model, no resume parsing, no generated match explanations beyond the
matched-skill list itself. "Skill-based opportunity matching (freelance +
full-time)" in the roadmap's task name is exactly this scorer; the posting/
application workflow the phrase might otherwise imply is not built here.

### Fork B — engagement-type semantics: **B1 (`OpportunityKind` — `freelance`/`full_time` — is informational only; it does not change matching behavior)**

The roadmap's "(freelance + full-time)" parenthetical names the two
engagement types the field must be ABLE to represent, not a request for
differentiated matching logic per type. `suggest_opportunity_match` scores
identically regardless of `kind` — a caller that wants freelance-only or
full-time-only results filters `Opportunity.kind` itself.

Rejected: B2 (weight or gate matches differently by `kind`, e.g. require a
higher skill-overlap threshold for full-time roles). An arbitrary product
decision with no disclosed rationale — the same category of rejection every
prior Fork-D/Fork-C weighting proposal in this tier has received (ADR-0016
Fork D's D2, ADR-0017 Fork D's D2, ADR-0018 Fork C's C2).

### Fork C — matching semantics: **C1 (symmetric set intersection: `subject_intent.offering ∩ opportunity.required_skills`)**

Unlike R-016's DIRECTIONAL complementary matching (seeking vs. offering
across two people) or R-017's directional stage-equality matching, R-021 is
naturally SYMMETRIC: a skill either satisfies a requirement or it does not
— there is no "opportunity offering, subject seeking" reciprocal direction
to model (an `Opportunity` does not itself "seek" or "offer" in the
`IntentProfile` sense; it simply lists requirements). Reusing `culture.py`'s
own symmetric tag-intersection model (rather than `intent.py`'s directional
one) is therefore the correct fit here, applied to a different pairing
(person vs. listing, not person vs. person).

Rejected: C2 (directional matching mirroring `intent.suggest_match`, e.g.
also modeling what the OPPORTUNITY can "offer" the subject — salary,
benefits — as a reciprocal tag set). A real, larger feature (compensation/
benefit matching) with no disclosed scope in the roadmap's task name; skill
requirements are the one thing "skill-based... matching" unambiguously
names.

### Fork D — tenant scope: **D1 (cross-tenant matching is explicitly ALLOWED — no tenant check at all)**

Reproduces ADR-0016/0017/0018/0020's identical reasoning: freelance/full-
time hiring across companies is definitionally cross-tenant — a subject in
tenant A must be able to match against an opportunity posted by tenant B.
`suggest_opportunity_match` / `rank_opportunities` do not inspect tenant at
all.

## What is deliberately NOT built here (named, not silently skipped)

- **No new "my skills" opt-in type.** Deliberately reuses R-016's
  `IntentProfile.offering` — see Fork A's rejection of A3.
- **No persistence.** `Opportunity` records are not stored; a caller
  supplies them each time, exactly as `intent.IntentProfile`/
  `career.CareerGoal` do before their own persistence follow-ups.
- **No REST/wire surface, no UI.** Nothing in `contracts/openapi.yaml`
  changes.
- **No opportunity-posting workflow.** No approval, no expiry, no applicant
  tracking, no "who may post" eligibility rule — this module only scores a
  caller-supplied `Opportunity`, it does not decide how one comes to exist
  or how long it stays valid.
- **No differentiated matching by `OpportunityKind`.** See Fork B.
- **No reciprocal opportunity-side matching (compensation, benefits).** See
  Fork C's rejection of C2.

## Consequences

- A genuinely useful, genuinely tested skill-based matching scorer exists
  for a future persistence/REST/posting-workflow task to build on, with the
  hard design questions (reuse vs. new opt-in type, symmetric vs. directional
  matching, engagement-type semantics, cross-tenant scope) already resolved
  and covered by `tests/domain/test_opportunity.py`.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change. The security review for this task
  is scoped accordingly — pure computation over caller-supplied domain
  objects, with no I/O.
- The roadmap's R-021 checklist line is intentionally NOT marked "the full
  10-16h skill-based opportunity matching vision shipped" — it is marked
  shipped as THIS scoped matching seam, exactly as
  R-012/R-016/R-017/R-018/R-020 were, with the deferred posting-workflow/
  persistence/REST halves named above as the obvious next slices.
