# ADR-0019 — DmPrivacy: a Deterministic, Mutual DM-Authorization Gate with
Granular Per-Field Exposure over the Peer-Networking Composition Seam (R-019)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0016 (R-016's `IntentProfile`/`suggest_match`, the Fork A/B
scope-down discipline this ADR reproduces unchanged), ADR-0017 (R-017's
`CareerGoal`/`suggest_trajectory_match`), ADR-0018 (R-018's `PeerSuggestion`/
`suggest_peer` — "the matching core" this ADR's `MATCHES_ONLY` audience choice
composes, unchanged, exactly as ADR-0018 composed ADR-0016/0017's own signals).

## Context

The roadmap names R-019 "Privacy-controlled DM portal (granular data exposure)
🏦 POST-INVESTMENT", the fourth task of Rendly's Phase 3 "B2C professional
networking (VISION)" tier (`R-016 -> R-026`, "Depends on: R-004/R-005 + the
matching core", "~10-16h each"). Like R-017/R-018 before it, R-019 has no
further roadmap detail beyond its title — this ADR resolves that title the
same way ADR-0016/0017/0018 resolved theirs.

Two things bound this task before any design choice is made, mirroring every
prior ADR in this tier's own Context section:

1. **"Portal" cannot honestly mean a REST endpoint or a UI here.** Every prior
   task in this tier (R-012, R-016, R-017, R-018) shipped as a pure-domain,
   no-persistence, no-REST seam and explicitly deferred the wire/UI layer to a
   named follow-up — Rendly has no frontend package at all, and this task has
   no persistence-backed settings store to build a real portal against.
   Building one here would repeat the exact A3/A4-shaped scope creep
   ADR-0016/0017/0018 already rejected for themselves. This run is unattended
   (no human available to resolve the resulting ambiguity mid-run), so the
   conservative reading is the one consistent with every seam this tier has
   shipped so far: "portal" describes the eventual vision layer, not
   something this task builds.
2. **"Privacy-controlled" cannot honestly default to permissive.** Unlike
   R-016/R-017/R-018 — where an un-opted-in user is simply excluded from
   matching (a neutral, low-stakes default) — a DM authorization gate that
   defaulted an un-opted-in user to reachable would be the opposite of
   "privacy-controlled": it would let anyone message a user who never made a
   choice. The one new design constraint R-019 introduces, that no prior
   task in this tier had to resolve, is a FAIL-CLOSED default (see Fork B).

R-019's own differentiator from R-016/R-017/R-018 is not a new matching
signal — the roadmap explicitly names its dependency as "the matching core"
(already fully shipped as R-016/017/018), not a new one. The one genuinely
new thing R-019 can honestly ship, without inventing a portal or a model, is
the AUTHORIZATION DECISION a real DM portal would need before it could ever
let two users exchange a message: a mutual opt-in check, optionally gated on
R-018's matching core, plus a granular (per-field, not all-or-nothing)
exposure decision — "granular data exposure" read honestly as exactly that,
not as a data-broker feature.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic authorization gate composing `peer.PeerSuggestion`; no REST endpoint, no persistence, no UI, no ML)**

`src/rendly/dm_privacy.py` adds three pieces, mirroring exactly how
R-012/R-016/R-017/R-018 shipped their own pure-domain seams:

- `DmPrivacySettings` (a new opt-in type — see Fork B) + `bind_dm_privacy_settings`
  (canonical construction path, mirrors `bind_intent_profile`/`bind_career_goal`).
- `DmAuthorization` (an immutable result carrying each side's `DmAudience`,
  each side's own `exposed_fields`, and the `PeerSuggestion` the decision
  relied on, if any) + `authorize_dm` (the pairwise decision — see Fork C for
  why there is no `rank_*`/bulk companion here, unlike R-016/017/018).
- `ProfileField` (the closed, 2-value set of `Profile` fields eligible for
  granular exposure — `org_role`/`team`, the two fields `profile.py`'s own
  docstring already names as internal-only / never on R-001's public `User`
  wire).

There is no new migration, no new table, no new REST route, and no
`policy.schema.json` touch — identical posture to ADR-0016/0017/0018 Fork A.

Rejected: A2 (an ML/embedding-based exposure-recommendation model). Same
rejection as ADR-0012/0016/0017/0018's own A2: no existing inference seam,
no training data, no honestly-bounded way to ship it in one task. Rejected:
A3 (build the REST endpoint + a `dm_privacy_settings` persistence/cache layer
in the same PR). A second, independent unit of work exactly as
ADR-0016/0017/0018's own A3/A4 rejections describe. Rejected: A4 (build a
real frontend "portal" — a settings page + inbox). Rendly has no frontend
package to extend, and inventing one here — with no backend REST surface to
call — would ship an unconnected UI shell, the same half-finished-
implementation failure mode the ecosystem's engineering standards forbid.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is the
pure-domain AUTHORIZATION GATE a real DM portal would call before letting two
users exchange a message — no REST endpoint, no persistence, no UI. "DM
portal" in the roadmap's task name is exactly this gate; the "portal"
language describes the eventual vision layer this gate is a scoped-down
placeholder for, not something this task builds — the same disclosure
pattern as every prior seam in this tier.

### Fork B — default posture: **B1 (fail-closed; `DmPrivacySettings` for BOTH sides is a required, non-`Optional` argument to `authorize_dm`, with no default `DmAudience`)**

Unlike `peer.suggest_peer`'s optional component signals (where an absent
`IntentProfile`/`CareerGoal` merely omits that component, mirrors
ADR-0018 Fork B), a DM authorization gate cannot treat an un-opted-in user as
silently reachable — that would be the opposite of "privacy-controlled".
`authorize_dm` therefore takes `subject_settings`/`candidate_settings` as
REQUIRED arguments (not `| None`): a caller with no settings for a user
simply cannot call this function for them, mirroring `intent.suggest_match`'s
required-pair shape (not `peer.suggest_peer`'s optional shape) precisely
because the default risk profile here is the opposite of R-018's. Within
`DmPrivacySettings` itself, `audience: DmAudience` has NO default value — a
caller minting a new settings object must make an explicit choice rather
than falling back to a permissive one.

Rejected: B2 (default `DmAudience` to `NOBODY` when unset, i.e. give the
field a default so `DmPrivacySettings` can be constructed without an
explicit choice). Silently encoding a "safe" default inside the type would
let application code forget to ask the user at all and still compile/run —
the explicit-required-argument shape at the FUNCTION boundary (this Fork)
plus the explicit-required-field shape at the TYPE boundary together make
"I forgot to ask" a `TypeError`/`ValidationError`, not a silent default.
Rejected: B3 (treat an absent settings object as an implicit `NOBODY`,
i.e. make `authorize_dm` accept `| None` and refuse internally). Functionally
equivalent to B1's outcome but strictly worse ergonomically and for
auditability — a caller reading `authorize_dm`'s signature could reasonably
assume `None` means "no preference, use default", conflating the "never
opted in" state with an explicit "I opted into being unreachable" state that
this module elsewhere (correctly) keeps distinct.

### Fork C — mutuality: **C1 (BOTH sides' `DmAudience` must independently permit the pairing; no unilateral "I want to DM you" bypass)**

Mirrors this module's own docstring "DELIBERATE DIVERGENCE FROM
`peer.suggest_peer`" section: `peer.py`'s composed signals report a
suggestion FOR a subject ABOUT a candidate (asymmetric by design, per
ADR-0018), but a DM is a two-way channel — `authorize_dm` requires BOTH
`subject_settings.audience` AND `candidate_settings.audience` to
independently evaluate to "permit" (`_permits`) before returning a
`DmAuthorization`. `DmAudience.MATCHES_ONLY` on either side is satisfied only
when a `peer.PeerSuggestion` connecting EXACTLY that pair is supplied — this
is the one dependency on "the matching core" the roadmap names; this module
does not recompute matching, it composes R-018's already-shipped result.

Rejected: C2 (authorization succeeds if EITHER side permits it). Would let a
permissive subject unilaterally message a candidate whose own settings
refused them — directly defeats "privacy-controlled". Rejected: C3 (only the
RECIPIENT's `DmAudience` matters, mirroring how most consumer chat products
gate "who can message me"). Real products do this, but doing it here would
mean the SUBJECT's own audience choice is never consulted even when the
subject themselves opted into `NOBODY` — inconsistent with this module's own
"absence/refusal is symmetric" posture and with `DmPrivacySettings`
documenting itself as governing whether a user "can be authorized to send OR
receive a DM ... on either side of a pair." A future task that wants
recipient-only semantics can build that as an explicit, named product
decision on top of this gate; this task does not make that call un-asked.

### Fork D — tenant scope: **D1 (cross-tenant DM authorization is explicitly ALLOWED — no tenant check at all)**

Reproduces ADR-0016 Fork B's / ADR-0017 Fork B's / ADR-0018 Fork D's
reasoning unchanged: this gate sits downstream of the R-018 matching core,
which already allows cross-tenant pairs (B2C professional networking is
definitionally cross-company) — a gate composing that signal must not
silently introduce a same-tenant restriction the signal it composes does not
have. `authorize_dm` does not inspect tenant at all; both tenant ids are
carried through onto the returned `DmAuthorization`.

Rejected: D2/D3 — identical to ADR-0016's/0017's/0018's own rejections
(reusing `culture.py`'s refusal "for safety" would silently defeat the
matching-core composition; an explicit per-tenant opt-in allow-list is a real
future feature this task is not positioned to decide un-asked).

**DELIBERATE NON-OVERLAP WITH R-005/R-006 (named, not silently conflated):**
this gate does NOT touch the REAL `rendly.realtime` chat runtime.
`enums.ChannelType.DM` channels (R-005/R-006) are tenant-scoped and
RLS-protected — an enterprise-internal concept entirely separate from this
cross-tenant B2C authorization gate. Wiring this gate to real DM-channel
creation is a follow-up task's job, not this one's, exactly as R-018 named
"no wiring to a real REST/UI" as deliberately out of scope for itself.

### Fork E — granular exposure: **E1 (`exposed_fields` is a per-side, opt-in, closed 2-value field selector reported independently — never merged, intersected, or defaulted to "all")**

"Granular data exposure" (the roadmap's own parenthetical) is read literally:
per-FIELD, not all-or-nothing. `ProfileField` is deliberately narrow — the
two fields `profile.py`'s own docstring already identifies as internal-only
(`org_role`, `team`) — rather than an open field-name string, so an invalid
or future-added `Profile` field cannot silently be "exposed" through a typo.
`exposed_fields` defaults to `()` (nothing) on `DmPrivacySettings`: exposure
is opt-IN per field, mirroring `IntentProfile.seeking`/`offering`'s own
opt-in tag discipline. `DmAuthorization` reports `subject_exposed_fields` and
`candidate_exposed_fields` SEPARATELY (never intersected or unioned) because
what each side reveals to the other is an independent decision — a caller
rendering "what can I see about them" and "what can they see about me" needs
both, unmerged.

Rejected: E2 (a single shared `exposed_fields` on the `DmAuthorization`,
computed as the intersection or union of both sides'). Would silently
conflate two independent decisions into one number with no disclosed
semantics (intersection reads as "mutually visible", union reads as "either
revealed" — both are real product interpretations with different privacy
implications, and picking one un-asked is exactly the kind of undisclosed
product decision this codebase's discipline (ADR-0018 Fork C's rejection of
C3, "no disclosed benefit at this scope") already rejects). Rejected: E3
(default `exposed_fields` to "all `ProfileField` values" once authorized,
i.e. authorization implies full exposure). Defeats "granular" entirely —
authorization (can we DM at all) and exposure (what do you learn about me)
are deliberately separate axes in this design; conflating them removes the
"granular" the roadmap explicitly asked for.

### Fork F — bulk/list variant: **F1 (no `rank_*`/bulk companion function; `authorize_dm` is single-pair only)**

Every prior seam in this tier (`intent.rank_matches`, `career.rank_
trajectory_matches`, `peer.rank_peers`) ships a bulk companion alongside its
pairwise function, because "suggest/rank the best N candidates from a pool"
is a genuinely useful, boundable operation for a SUGGESTION. DM authorization
is not a suggestion over an unranked pool — it is a binary decision about ONE
already-identified counterpart (a specific person a user is trying to
message), so there is no "top-N" to rank. A bulk "list everyone I'm
authorized to DM" operation would additionally require a full candidate-pool
enumeration this task does not own — identical to ADR-0016's/0017's/0018's
own "No candidate-pool eligibility/discovery" exclusion, which names R-024
(Discovery feed) as the natural owner of deciding which candidates a subject
is even shown.

Rejected: F2 (add `authorized_dm_peers`, a bulk variant paralleling
`rank_peers`, that evaluates `authorize_dm` over a caller-supplied candidate
pool and returns only the authorized subset). Superficially consistent with
the sibling modules' shape, but adding it here would be building a feature
nothing in the roadmap or this task's own reasoning asked for (the
engineering standards' "don't design for hypothetical future requirements"
apply as much to matching an established pattern as to any other kind of
scope creep) — a future task that needs bulk evaluation can add it
trivially by calling `authorize_dm` in a loop over a pool it already has
from R-024, with no design decision left unresolved by this ADR.

## What is deliberately NOT built here (named, not silently skipped)

- **No real B2C consumer identity.** `authorize_dm` operates over the
  existing enterprise `Profile` (R-002) plus the existing matching-core
  types (R-016/017/018) as a placeholder actor model, identical posture to
  every prior seam in this tier. R-023 (Consumer onboarding) remains the
  natural owner of a real, non-tenant-scoped B2C identity.
- **No persistence.** No new store, no new Alembic migration. A follow-up
  task owns wiring `DmPrivacySettings` to a real per-user settings store.
- **No REST/wire surface, no frontend, no real DM-channel wiring.** Nothing
  in `contracts/openapi.yaml` or `contracts/rendly-domain.schema.json`
  changes, no frontend package is added, and this gate is not wired to the
  real R-005/R-006 `ChannelType.DM` chat runtime (see Fork D's "DELIBERATE
  NON-OVERLAP" note). A follow-up task owns the contract addition, the
  FastAPI router, the actual "portal" UI, and the real channel-creation
  wiring.
- **No candidate-pool eligibility/discovery, no bulk/list variant.** See
  Fork F — identical disclosed limitation to every prior seam in this tier.
- **No new matching signal.** This task composes R-018's already-shipped
  `PeerSuggestion`; it does not add a third matching dimension.

## Consequences

- A genuinely useful, genuinely tested DM-authorization CORE exists for a
  future persistence/REST/identity/UI task to build the actual "portal" on
  top of, with the hard design questions (fail-closed default, mutuality,
  granular exposure reporting, cross-tenant handling, matching-core
  composition) already resolved and covered by
  `tests/domain/test_dm_privacy.py`.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change. The security review for this task
  is scoped accordingly — pure computation over caller-supplied domain
  objects, with no I/O, mirroring ADR-0016's/0017's/0018's own Consequences.
  The fail-closed default (Fork B) and mutual gate (Fork C) are the two
  properties a security review should verify hold under adversarial input
  (e.g. a caller cannot pass a `PeerSuggestion` for a different pair to
  smuggle a `MATCHES_ONLY` authorization through — enforced by
  `_require_connects_pair`, raising rather than silently ignoring a
  mismatched suggestion).
- The roadmap's R-019 checklist line is intentionally NOT marked "the full
  10-16h privacy-controlled DM portal vision shipped" — it is marked shipped
  as THIS scoped authorization-gate seam, exactly as
  O-009/O-010/O-011/R-012/R-013/R-014/R-015/R-016/R-017/R-018 were, with the
  deferred identity/persistence/REST/UI/discovery/channel-wiring halves
  named above as the obvious next slices.
