# ADR-0026 — Creator Economy Features: a Deterministic, Tier-Gated Revenue-Share Allocation Seam (R-026)

Status: Accepted
Date: 2026-07-10
Builds on: ADR-0025 (`premium.py`'s `PremiumTier`/`PremiumEntitlement`/
`has_feature_access` seam, extended here by one closed feature member, not
restructured), ADR-0024 (`discovery_feed.py`'s "compose a sibling module's
already-public surface, do not modify the sibling beyond an invited extension
point" pattern), the whole B2C professional-networking tier's established
"scoped seam, ADR-disclosed limitation, honesty boundary" discipline
(ADR-0016 through ADR-0025).

## Context

The roadmap names R-026 "Creator economy features 🏦 POST-INVESTMENT", the
eleventh and final task of Rendly's Phase 3 "B2C professional networking
(VISION)" tier — the first still-unchecked `R-` line in
`anoryx-ecosystem-roadmap-v3.md`'s checklist as of this run. Unlike every prior
task in this tier, R-026 is not given its own descriptive paragraph in the
roadmap body — it appears only as a name in the tier's shared task list, with
the tier's shared estimate/dependency/risk line ("~10-16h each · Depends on:
R-004/R-005 + the matching core · Risk: Medium"). This run treats that absence
of detail the same way it treats every other genuine ambiguity in an unattended
run (per this run's own operating instructions): resolve it with the most
conservative, smallest honestly-buildable reading, name the reading explicitly,
and do not widen scope to fill in the blanks.

"Creator economy" is a large product space (content publishing, tipping,
subscriptions, payouts, follower/subscriber relationships, analytics). Building
any of that for real would mean one of: (a) real payment collection — which
R-025's own ADR-0025 already named as a DIFFERENT, not-yet-dispatched
cross-product task (X-005) that this builder cannot reach into (Delta's ledger
is a different subproject folder); or (b) inventing a large, unrequested
persistence/relationship/publishing surface with no existing behavior to
compose — exactly what ADR-0018/ADR-0024/ADR-0025's own Fork A/B discipline
already rejects for this tier.

What every "creator economy" actually needs, underneath the payment
mechanics, is a rule for HOW a creator's earnings get split between the
creator and the platform — and this codebase already has, from R-025, exactly
the primitive needed to make that rule tier-aware without inventing anything
new: `premium.py`'s `PremiumEntitlement`/`has_feature_access`. This ADR
resolves R-026 as the smallest honest slice of "creator economy": the
split-percentage RULE itself, expressed as pure computation, with real money
movement named explicitly as unbuilt.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure, closed-form percentage-split ALLOCATION calculator over a caller-supplied integer total, tier-gated via a new `premium.py` feature; NOT payment collection, NOT payout, NOT any follower/content/persistence surface, NOT any Delta wiring)**

`src/rendly/creator.py` adds `CreatorEarningsAllocation` (an immutable,
self-validating split result) and `allocate_creator_earnings` (the
deterministic split function), composing `premium.has_feature_access` via one
new closed `PremiumFeature` member, `CREATOR_REVENUE_SHARE_BOOST`.

Rejected: A2 (build real payout/collection — a payment-processor integration
or a wiring of computed shares into Delta's ledger). This is not just larger
scope, it is a DIFFERENT roadmap task's territory: R-025/ADR-0025 already named
"monetization (via Delta)" as X-005's job, a separate, still-unshipped,
cross-product task, and Rendly's builder has no write access to Delta's ledger
regardless of task framing. Rejected: A3 (a follower/subscriber relationship
model, or a content-publishing/posting surface). Real, but a substantially
larger, unrequested feature with no existing behavior in this codebase to
compose against — exactly the kind of invented scope ADR-0018 Fork A and
ADR-0025 Fork A/B2 already rejected for this tier. Rejected: A4 (ship nothing /
a stub). "Creator economy features" names real, schedulable work, and a
revenue-share rule is a genuine, honestly-buildable gap: nothing in this
codebase today expresses "how much of a payment does a creator keep" — this
ADR closes exactly that gap, no more.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
percentage-split RULE only — it never collects, moves, or stores real money,
never hosts creator content, never models a follower relationship, and is not
wired to Delta in any way. "Creator economy features" as a full product
remains almost entirely unbuilt; this ADR closes one narrow, real sub-problem
of it (the split rule) and names everything else explicitly, below.

### Fork B — tier-gating mechanism: **B1 (compose `premium.py` by adding one new closed `PremiumFeature` member + its `_FEATURE_MIN_TIER` entry; `creator.py` calls `has_feature_access`, it does not re-implement tier/expiry logic)**

`premium.py`'s own docstring explicitly invited this: "the mapping is
deliberately keyed PER FEATURE ... so a future feature requiring a different
minimum tier is a one-line addition here, not a restructuring." Adding
`CREATOR_REVENUE_SHARE_BOOST` (mapped to `PremiumTier.PREMIUM`, the same
minimum every existing feature already uses) is exactly that one-line
addition — it does not touch `PremiumTier`, `PremiumEntitlement`,
`has_feature_access`'s fail-closed/expiry logic, or either of R-025's two
existing compositions (`resolve_discovery_feed_limit`/
`resolve_mentorship_match_limit`).

Rejected: B2 (a separate, `creator.py`-local tier/entitlement concept, e.g. a
`CreatorTier` distinct from `PremiumTier`). Would duplicate R-025's
fail-closed/expiry-checking logic instead of reusing it, and would give Rendly
two competing "is this user premium" answers for what a caller would
reasonably expect to be one fact about one user. Rejected: B3 (no tier-gating
at all — one fixed split for every creator). Would waste the one thing R-025
already built for exactly this kind of "premium unlocks something better"
composition, and would make "creator economy" indistinguishable from a single
hard-coded constant.

### Fork C — the split table: **C1 (a small, closed, two-row basis-point table: 70/30 base, 85/15 boosted — no third tier, no per-creator/per-tenant override)**

Two rows only, mirroring `premium.py`'s own Fork B rejection of an open/
dynamic feature catalog: the percentages are fixed constants
(`_BASE_CREATOR_SHARE_BPS`/`_BOOSTED_CREATOR_SHARE_BPS`), not a
runtime-configurable table, not a per-tenant or per-creator override, and not
sourced from any external pricing/config service (none exists in Rendly).
Basis points (integers out of 10,000) are used instead of a float percentage,
extending Delta's own "money is integer minor units, never floats" invariant
to the percentage math as well — the split multiplies and divides only
integers, never a `float`.

Rejected: C2 (a dynamic, ops-editable split-percentage config). A real, but
larger, unrequested feature (persisted config + an admin surface to edit it —
squarely D-007/ops territory transplanted into Rendly), the same reasoning
ADR-0018 Fork A and ADR-0025 Fork A/A4 already used to reject inventing
persisted, admin-editable config in this tier. Rejected: C3 (a three-or-more
tier scale, or per-feature-specific splits). No product requirement or
existing precedent motivates more than the two rows R-025 already uses for
every other `PremiumFeature` — inventing more tiers here would be the one
inconsistent seam in an otherwise two-tier product.

### Fork D — rounding remainder: **D1 (floor the creator's share; the entire integer-division remainder is assigned to the platform share, never the creator's)**

`creator_share = (total * share_bps) // 10_000`; `platform_share = total -
creator_share`. The two ALWAYS sum to `total_minor_units` exactly (enforced
structurally by `CreatorEarningsAllocation`'s own validator, not just by the
function that builds it) — no minor unit is ever lost or invented by rounding.
Assigning the remainder to the platform, not the creator, is the conservative
choice consistent with this run's own operating instruction to make the most
conservative choice under ambiguity: a creator is never handed a fractional
minor unit their exact percentage does not support.

Rejected: D2 (remainder to the creator). Would mean a creator's actual share
occasionally exceeds their nominal percentage (however trivially — at most one
minor unit), which is the less conservative of the two equally-valid rounding
choices with no product requirement forcing it. Rejected: D3 (banker's
rounding / round-half-to-even across the two shares). Unnecessary complexity
for a two-way split where "one side gets the whole remainder" already
guarantees an exact, lossless, deterministic total — this task's own operating
instructions favor the simplest choice that satisfies the invariant, not the
most elaborate one.

### Fork E — time handling: **E1 (`now` is always caller-supplied; mirrors `premium.py`'s own D1)**

`allocate_creator_earnings` takes `now` as an explicit keyword-only parameter
purely to pass through to `has_feature_access` — this module itself performs
no time-based logic of its own, it delegates entitlement/expiry evaluation
entirely to `premium.py`. Rejected: E2 (read the wall clock internally). Would
make this module non-deterministic for no reason, when `premium.py` already
established the caller-supplied-`now` discipline this module simply inherits.

## What is deliberately NOT built here (named, not silently skipped)

- **No real payment collection, payout, or transfer of funds.** This module
  never moves money — it only ever computes how a caller-supplied integer
  total SHOULD be split. See Fork A/A2.
- **No wiring to Delta's ledger or budget engine.** Real money movement
  remains a future, separate, still-unshipped cross-product task (in the same
  spirit as R-025's own X-005 deferral), and this builder cannot reach into
  Delta's ledger regardless (a different subproject folder).
- **No content-publishing surface, no follower/subscriber relationship, no
  persistence for anything in this module.** A caller supplies the profile,
  entitlement, and total each time — no new table, no new migration.
- **No REST/wire surface, no UI, no pricing/plan display.** Nothing in
  `contracts/openapi.yaml` changes.
- **No dynamic/ops-configurable split-percentage catalog.** See Fork C — the
  split table is a small, closed, fixed set of two rows.
- **No third tier, no per-tenant/per-creator override, no negotiated rate.**

## Consequences

- Rendly's domain layer gains its first creator-economy primitive: a
  deterministic, lossless, tier-aware answer to "how should this payment be
  split between this creator and the platform right now" — composable by any
  future caller (a future REST/UI layer, or a future Delta-wiring task)
  without that caller re-deriving the rounding/tier-gating logic itself.
- `premium.py` gains one new closed feature member
  (`CREATOR_REVENUE_SHARE_BOOST`) via the one-line extension point its own
  docstring already invited; `PremiumTier`, `PremiumEntitlement`,
  `has_feature_access`'s fail-closed/expiry semantics, and R-025's two existing
  compositions are all untouched.
- No new attack surface is introduced: no new network endpoint, no new table,
  no new migration, no RLS change, no new identifier type, no outbound call to
  any payment processor, no float anywhere in the money-shaped math — pure
  integer computation over caller-supplied domain objects, no I/O.
- The roadmap's R-026 checklist line is intentionally NOT marked "the full
  real creator economy (publishing + follower relationships + payouts)
  shipped" — it is marked shipped as THIS scoped revenue-share allocation
  seam, exactly as R-012/R-016 through R-025 were, with every deferred piece
  named above as the obvious next slice for a future, separately-dispatched
  task.
