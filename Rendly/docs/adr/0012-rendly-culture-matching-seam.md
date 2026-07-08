# ADR-0012 — Culture Matching: a Deterministic, Opt-In, Cross-Department Suggestion Seam (R-012)

Status: Accepted
Date: 2026-07-08
Builds on: ADR-0002 (R-002's ``Profile`` / ``bind_profile`` canonical-construction idiom, which
``CultureOptIn`` / ``bind_culture_opt_in`` reproduce), ``rendly-domain.schema.json``'s own
non-removable honesty boundary about ``Profile`` and "intent" (distinguished, not superseded — see
Context).

## Context

The roadmap names R-012 "AI-powered internal culture matching engine 🏦 POST-INVESTMENT... Connect
employees across departments to build collaborative corporate culture (internal, privacy-controlled).
Depends on: R-004, R-002 · 16-22h · Complex." It is the first task pulled from Rendly's 🏦
POST-INVESTMENT tier (Phase 2, "Enterprise culture + events") into an active build, following the
precedent set by O-009/O-010/O-011 (also 🏦, also shipped as a deliberately SCOPED-DOWN seam rather
than the full vision description).

Two things bound this task before any design choice is made:

1. **The name is aspirational, the delivery is not.** "AI-powered" describes the funded-future
   vision; a real ML matching/embedding pipeline is a multi-week, its-own-ADR undertaking (model
   choice, training data, drift, cost) with no existing seam to hang it on (Rendly has no ML
   inference infra anywhere in the codebase yet). Building it now, unasked and un-budgeted, would
   be exactly the kind of scope-widening the root CLAUDE.md and banked rule 13 warn against
   ("Lean STEP-0 forks = smaller attack surface... default to the minimal option").
2. **``rendly-domain.schema.json`` already carries a non-removable honesty boundary**: "'intent'
   reduces to a User's org-role + team-affiliation fields ONLY... NO matching algorithm here —
   intent-based matching is the post-investment tier (R-016 -> R-026) and is deferred." That
   sentence is about ``Profile`` never growing an ``Intent``/preference-vector entity, and about
   the R-016 B2C "intent-based matching" track specifically. R-012 is a DIFFERENT, enterprise-only
   track (Phase 2, not Phase 3's B2C tier) and this ADR introduces NO ``Intent`` entity and NO
   change to ``Profile`` at all — ``CultureOptIn`` is a new, separate, additive model. This ADR
   does not touch, weaken, or contradict that boundary; it is called out here so a future reader
   does not mistake one deferral for silently licensing the other.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic tag-overlap seam; no REST endpoint, no persistence, no ML)**
``src/rendly/culture.py`` adds ``CultureOptIn`` (an explicit, per-user consent record: ``user_id``,
``tenant_id``, a bounded ``interests`` tag tuple, ``opted_in_at``) and a pairwise/ranking scorer
(``suggest_connection`` / ``rank_connections``) that operates on already-loaded ``Profile`` +
``CultureOptIn`` pairs — mirroring exactly how R-002 shipped a domain-only model before R-004 added
persistence. There is no new migration, no new table, no new REST route, and no ``policy.schema.json``
touch (out of scope for this product entirely).

Rejected: A2 (an ML/embedding-based similarity model). No existing inference seam, no training
data, no disclosed way to keep it honestly-bounded within one task — deferred to whenever the
funded vision actually specs it. Rejected: A3 (build the REST endpoint + an opt-in persistence
table in the same PR). That is a second, independent unit of work (an Alembic migration, RLS
policy, a DB test lane, a wire-contract addition to ``contracts/openapi.yaml``) or none of it is
"done" per the roadmap's own bar; bundling it here risks shipping either half-finished. The
compute-only seam is fully useful and fully testable on its own (exactly as R-002 was before R-004),
so it ships alone and the wiring is a named follow-up (see Consequences).

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a DETERMINISTIC tag-overlap
scorer — set-intersection size, nothing learned, nothing probabilistic. "AI-powered" is the vision
name for a future, not-yet-built capability; this task does not claim to be it.

### Fork B — privacy control: **B1 (opt-in is structural, not a flag to check)**
There is no boolean "matching_enabled" field on ``Profile`` to forget to consult. A user who has
never called ``bind_culture_opt_in`` simply has no ``CultureOptIn`` object, and every function in
this module REQUIRES one as an argument for both the subject and every candidate — there is no code
path that can compute a suggestion, or even iterate a user's interests, without that user's own
prior, explicit opt-in object in hand. This mirrors ``bind_membership``'s own structural (not
runtime-checked) tenant-agreement guarantee (ADR-0002 §7): the invariant is enforced by what the
function signature demands, not by an ``if`` a future caller could skip.

Rejected: B2 (an opt-OUT model — matching runs by default, users can disable it). Directly
contradicts "privacy-controlled" as the roadmap states it; default-on cross-department suggestion
of who-has-what-interests is a real workplace privacy surface (interest tags can correlate with
protected characteristics, health, religion, politics) and must be affirmative-consent, not a
default with an escape hatch.

### Fork C — cross-department rule: **C1 (exclude a pair only when BOTH have a non-null, EQUAL team; unknown-team pairs are still eligible)**
The point of R-012 is bridging department silos that R-006's team-mapped channels do not reach —
two people already in the SAME known team are already reachable through that existing seam, so
suggesting them again adds nothing. But requiring BOTH profiles to carry a team would silently
exclude anyone without one (contractors, a not-yet-assigned new hire, a flat org with no team
concept) from ever appearing as a candidate at all, which is a worse and less-disclosed failure
mode than occasionally suggesting two people who might (unknowably, from this data) share a team.

Rejected: C2 (require both to have a non-null team, matching only cross-team pairs). Rejected for
the silent-exclusion reason above. Rejected: C3 (ignore team entirely — score every pair purely on
interest overlap). Rejected: fails the task's own "across departments" framing outright for the
common case where both sides DO have a known, equal team on file.

### Fork D — scoring + determinism: **D1 (score = shared-interest-tag count; ties break on candidate_user_id ascending; hard-capped inputs)**
``score`` is simply ``len(shared_interests)`` — legible, auditable, reproducible; a caller (or a
future reviewer) can recompute any suggestion by hand from the two opt-in records. Ranking sorts by
``(-score, candidate_user_id)`` so the SAME input always produces the SAME output — no hidden
randomness, no recency/last-write bias. ``interests`` per opt-in is capped at ``MAX_INTERESTS=16``
(mirrors this codebase's existing bounded-list discipline: ``detectors`` maxItems 16, ``ice_servers``
maxItems 16); a single ``rank_connections`` call is capped at ``MAX_CANDIDATES=500`` input pairs and
``MAX_SUGGESTIONS=50`` output rows (``limit`` is clamped, never trusted verbatim) — the pairwise
scorer is O(n\*m) and both bounds exist so neither the interest-tag list nor the candidate pool is
an unbounded-cost/DoS vector for a future caller that forgets to page its own input.

Rejected: D2 (a weighted/normalized score, e.g. Jaccard similarity). Adds a division and a
"similarity out of what" question with no disclosed benefit at this scope; a plain count is
simpler, equally orderable, and does not imply a precision this deterministic scorer does not have.

## What is deliberately NOT built here (named, not silently skipped)

- **No persistence.** ``CultureOptIn`` records are not stored; a caller must supply them (e.g. from
  an in-memory fixture, or a future opt-in store) each time. A follow-up task owns an
  ``rendly.culture`` Postgres table (RLS, same posture as ``profiles``) + an Alembic migration.
- **No REST/wire surface.** Nothing in ``contracts/openapi.yaml`` changes; there is no
  ``POST /v1/users/me/culture-opt-in`` or ``GET /v1/users/me/connection-suggestions`` yet. A
  follow-up task owns the contract addition (new locked schema + scope decision, mirroring how
  R-008 deferred its own admin-read surface in ADR-0008 Fork B) and the FastAPI router wiring it to
  this module's pure functions.
- **No revocation/expiry policy for an opt-in.** Because there is no persistence yet, "revoke" is
  simply "the caller stops supplying that user's ``CultureOptIn`` object" — a real revoke/TTL story
  belongs with the persistence follow-up.

## Consequences

- A genuinely useful, genuinely tested, privacy-controlled-by-construction seam exists for the next
  task to persist and expose over HTTP, with the hard design questions (what counts as a match, what
  is excluded, how ties break, what the DoS bounds are) already resolved and covered by
  ``tests/domain/test_culture.py``.
- No new attack surface is introduced: no new network endpoint, no new table, no new migration, no
  RLS change. The security review for this task is scoped accordingly — a pure computation over
  caller-supplied domain objects, with no I/O.
- The roadmap's R-012 checklist line is intentionally NOT marked "the full 16-22h vision shipped" —
  it is marked shipped as THIS scoped seam, exactly as O-009/O-010/O-011 were, with the deferred
  persistence/REST halves named above as the obvious next slice.
