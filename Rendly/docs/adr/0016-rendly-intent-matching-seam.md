# ADR-0016 — Intent Matching: a Deterministic, Complementary-Intent Matching Core (R-016)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0002 (R-002's `Profile` / `bind_profile` canonical-construction
idiom, which `IntentProfile` / `bind_intent_profile` reproduce, and its own
non-removable honesty boundary this ADR resolves — see Context), ADR-0012 (R-012's
precedent for scoping a 🏦 POST-INVESTMENT task down to a pure-domain,
no-persistence, no-REST seam; the same discipline ADR-0013/0014/0015 also followed).

## Context

The roadmap names R-016 "Intent-based matching algorithm (B2C) 🏦 POST-INVESTMENT",
the first task of Rendly's Phase 3 "B2C professional networking (VISION)" tier
(grouped `R-016 -> R-026`, "Depends on: R-004/R-005 + the matching core", "~10-16h
each"). R-016 is explicitly named as "the matching core" the rest of that tier
(R-017 profile optimization, R-018 peer-networking UI, R-021 skill-based
opportunity matching, R-022 mentorship matching, ...) is expected to build on.

Two things bound this task before any design choice is made:

1. **`rendly-domain.schema.json` and `profile.py` already carry a non-removable
   honesty boundary naming this exact task**: "'intent' reduces to a User's
   org-role + team-affiliation fields ONLY... NO matching algorithm here —
   intent-based matching is the post-investment tier (R-016 -> R-026) and is
   deferred." R-016 is precisely the task that boundary reserves for introducing
   an `Intent` concept — this ADR does not weaken or remove that boundary, it
   is the deferred work it named. `Profile` itself is untouched: no `Intent`
   field is added to it, mirroring how ADR-0012's `CultureOptIn` was additive,
   not a `Profile` change.
2. **"B2C" does not yet have a foundation to build on.** R-023 (Consumer
   onboarding) is unshipped — Rendly has no consumer identity/auth model outside
   the existing enterprise, tenant-scoped `Profile` (R-002). A genuine B2C
   matching PRODUCT needs onboarding, a discovery feed (R-024), and a DM portal
   (R-019) — none of which exist. Building real B2C identity from scratch inside
   this task would be exactly the kind of scope-widening banked rule 13 and
   ADR-0012's own precedent warn against. What CAN be built now, honestly, is the
   matching ALGORITHM CORE the roadmap explicitly names — the hard, reusable
   design problem (what counts as a match, how ties break, what the DoS bounds
   are) — decoupled from the consumer-identity question, exactly as R-002's
   domain model shipped independently of R-004's persistence.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic complementary-intent matching seam; no REST endpoint, no persistence, no B2C identity model, no ML)**

`src/rendly/intent.py` adds `IntentProfile` (an explicit, per-user opt-in record:
`user_id`, `tenant_id`, bounded `seeking`/`offering` tag tuples, `opted_in_at`) and
a pairwise/ranking scorer (`suggest_match` / `rank_matches`) that operates on
already-loaded `Profile` + `IntentProfile` pairs — mirroring exactly how R-012
shipped `culture.py` as a pure-domain seam over the same `Profile` type, and how
R-002 shipped domain-only before R-004 added persistence. There is no new
migration, no new table, no new REST route, and no `policy.schema.json` touch.

Rejected: A2 (an ML/embedding-based similarity or ranking model — e.g. resume/bio
text embeddings). No existing inference seam in this codebase, no training data,
no disclosed way to keep it honestly-bounded within one task — deferred to
whenever the funded vision actually specs it (same rejection ADR-0012 Fork A
already made for culture matching). Rejected: A3 (build a real B2C
identity/onboarding model in this task so matching has "real" B2C users to run
over). That is R-023's job — a separate, larger foundation task (auth model,
consumer signup flow, a non-tenant-scoped user concept) that this task's 10-16h
budget cannot honestly absorb alongside the matching algorithm itself. Rejected:
A4 (build the REST endpoint + an opt-in persistence table in the same PR). A
second, independent unit of work (an Alembic migration, an RLS posture decision —
notably harder here than R-004's tenant-RLS model, since B2C matching is
explicitly cross-tenant, see Fork B — a wire-contract addition); bundling it here
risks shipping either half-finished, exactly the failure mode ADR-0012/0013/0014/
0015 all avoided the same way. The compute-only seam is fully useful and fully
testable on its own, so it ships alone and the identity/persistence/REST wiring
are named follow-ups (see Consequences).

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a DETERMINISTIC
complementary-tag scorer — set-intersection across `seeking`/`offering`, nothing
learned, nothing probabilistic — operating over the EXISTING enterprise `Profile`
domain as a placeholder actor model, NOT a real B2C consumer identity (R-023
remains unshipped and unaddressed by this task). "Intent-based matching algorithm"
in the roadmap's task name is exactly what ships; "(B2C)" describes the eventual
consumer surface this core is meant to be reusable for, not something this task
builds.

### Fork B — tenant scope: **B1 (cross-tenant matching is explicitly ALLOWED — no tenant check at all)**

`culture.suggest_connection` (R-012) REFUSES a cross-tenant pair with a
`ValueError`, because internal cross-DEPARTMENT matching within one company must
never leak across companies. R-016 is definitionally the opposite: professional
networking that does not cross company lines is not "B2C professional
networking", it is just R-012 again. `suggest_match` / `rank_matches` therefore do
not inspect `subject_profile.tenant_id` vs. `candidate_profile.tenant_id` at all —
both are simply carried through onto the returned `IntentMatch` so a caller can
see them.

Rejected: B2 (reuse `culture.py`'s cross-tenant refusal here too, "for safety").
Would silently make R-016 unable to do the one thing its own name describes,
which is worse than the honest "this seam doesn't gate tenancy, a future
persistence/eligibility layer must" disclosure below. Rejected: B3 (require an
explicit opt-in flag per counterparty tenant, e.g. an allow-list of tenants
willing to be matched against). A real feature, but a product/policy decision
this task is not positioned to make un-asked — named as a future consideration,
not built here.

**Disclosed limitation:** this pure-compute seam has no way to know, and does not
attempt to decide, WHICH candidates a real deployment should even be allowed to
place in a subject's candidate pool (e.g. a company that wants to opt OUT of
appearing as candidates for other companies' employees). That eligibility
decision necessarily belongs to whatever future persistence/candidate-pool loader
supplies `rank_matches`'s `candidates` argument — this module trusts its input
exactly as `culture.rank_connections` already does for its own (same-tenant)
candidate pool.

### Fork C — matching semantics: **C1 (directional/complementary: `subject.seeking ∩ candidate.offering`, plus the mirror `subject.offering ∩ candidate.seeking`)**

"Intent-based" matching is about complementary WANTS (a mentor and a mentee, a
co-founder-seeker and a co-founder-offerer), not shared hobbies. A plain
symmetric tag-intersection scorer (`culture.py`'s model, reused verbatim) cannot
express this: two people who both listed `"mentor"` under `seeking` share a tag
but are a BAD match (both want the same thing from someone else), while a
`seeking=("mentor",)` subject and an `offering=("mentor",)` candidate share no
literal tag under the same field but ARE a good match. `suggest_match` therefore
scores two independent directional overlaps and sums them, returning which tags
matched on which side so a caller can explain the match rather than just a bare
number.

Rejected: C2 (reuse `culture.suggest_connection`'s symmetric same-field
intersection as-is). Produces exactly the "both want the same thing" false
positives above and would silently misrepresent what "intent-based" means.
Rejected: C3 (a fixed vocabulary + a hand-authored complement map, e.g.
`"mentor"` canonically complements `"mentee"`). Adds a real product surface (who
maintains the map? what happens to an unmapped tag?) with no disclosed benefit at
this scope — tags stay opaque strings and it is the CALLER's job to use a
consistent vocabulary (e.g. both sides literally tag `"mentor"`) for a
complementary match to be found, exactly as `culture.py` leaves tag semantics to
its caller.

### Fork D — scoring + determinism: **D1 (score = sum of both directional overlap counts; ties break on `candidate_user_id` ascending; hard-capped inputs)**

Mirrors `culture.py`'s `MAX_INTERESTS`/`MAX_CANDIDATES`/`MAX_SUGGESTIONS`
discipline exactly: `seeking` and `offering` are each capped at `MAX_TAGS = 16`;
a single `rank_matches` call is capped at `MAX_CANDIDATES = 500` input pairs and
`MAX_SUGGESTIONS = 50` output rows (`limit` is clamped, never trusted verbatim).
`rank_matches` sorts by `(-score, candidate_user_id)` so the SAME input always
produces the SAME output.

Rejected: D2 (weight `matched_as_seeker` and `matched_as_offerer` differently,
e.g. prioritize "what I'm seeking" matches over "what I can offer" matches).
Adds an arbitrary weighting decision with no disclosed product rationale; an
unweighted sum is simpler, equally orderable, and does not imply a prioritization
this deterministic scorer has no basis for.

## What is deliberately NOT built here (named, not silently skipped)

- **No real B2C consumer identity.** This seam operates over the existing
  enterprise `Profile` (R-002) as a placeholder actor model. R-023 (Consumer
  onboarding) remains unshipped and is the natural owner of a real, non-tenant-
  scoped B2C identity; a future revision of this module (or a sibling one) would
  bind `IntentProfile` to that identity instead of `Profile` once it exists.
- **No persistence.** `IntentProfile` records are not stored; a caller must
  supply them each time. A follow-up task owns an `rendly.intent_profiles` store
  (with an explicit answer to the cross-tenant RLS/eligibility question Fork B
  disclosed — notably harder than `culture.py`'s same-tenant table would be) +
  an Alembic migration.
- **No REST/wire surface.** Nothing in `contracts/openapi.yaml` changes. A
  follow-up task owns the contract addition and the FastAPI router wiring it to
  this module's pure functions (mirroring R-012's own deferred REST half).
- **No candidate-pool eligibility/discovery.** See Fork B's disclosed
  limitation — R-024 (Discovery feed) is the natural home for deciding which
  candidates a subject is even shown.
- **No revocation/expiry policy.** Because there is no persistence yet, "revoke"
  is simply "the caller stops supplying that user's `IntentProfile`" — a real
  revoke/TTL story belongs with the persistence follow-up.

## Consequences

- A genuinely useful, genuinely tested, complementary-intent matching CORE exists
  for R-017/R-018/R-021/R-022 and a future persistence/REST/identity task to
  build on, with the hard design questions (what counts as a match, how it
  differs from R-012's symmetric model, how cross-tenant is handled, what the DoS
  bounds are) already resolved and covered by `tests/domain/test_intent.py`.
- No new attack surface is introduced: no new network endpoint, no new table, no
  new migration, no RLS change. The security review for this task is scoped
  accordingly — a pure computation over caller-supplied domain objects, with no
  I/O.
- The roadmap's R-016 checklist line is intentionally NOT marked "the full
  10-16h B2C vision shipped" — it is marked shipped as THIS scoped matching-core
  seam, exactly as O-009/O-010/O-011/R-012/R-013/R-014/R-015 were, with the
  deferred identity/persistence/REST/discovery halves named above as the obvious
  next slices.
