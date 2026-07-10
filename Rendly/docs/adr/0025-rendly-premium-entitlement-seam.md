# ADR-0025 — Premium Features + Monetization (B2C, via Delta): a Deterministic, Fail-Closed Feature-Entitlement Seam (R-025)

Status: Accepted
Date: 2026-07-10
Builds on: ADR-0016 through ADR-0024 (the whole B2C professional-networking tier's
established "scoped seam, ADR-disclosed limitation, honesty boundary" discipline),
ADR-0019 (`privacy.py`'s fail-closed "absence means deny" default, the direct
precedent this ADR's Fork C reuses), ADR-0024 (`discovery_feed.py`'s "compose
already-public constants from a sibling module, do not modify that module" pattern,
the direct template Fork A's two concrete compositions follow).

## Context

The roadmap names R-025 "Premium features + monetization (B2C, via Delta) 🏦
POST-INVESTMENT", the tenth task of Rendly's Phase 3 "B2C professional networking
(VISION)" tier — the first still-unchecked `R-` line in
`anoryx-ecosystem-roadmap-v3.md`'s checklist as of this run. Every prior task in
this tier (R-012, R-016 through R-024) resolved the same fork: ship the full,
roadmap-implied vision, or ship a scoped, honestly-disclosed seam consistent with
this tier's established discipline. This ADR resolves that fork for R-025.

R-025's task name has two halves. "Premium features" names a feature-gating
concept this codebase does not yet have. "Monetization (via Delta)" names actual
money movement — and the roadmap's own cross-product checklist already lists the
task that would build that half separately and explicitly:
`X-005 — Rendly ↔ Delta monetization wiring 🏦, "Depends on: R-025, D-003"` — i.e.
X-005 is the wiring task, and R-025 (this task) is one of its two named
prerequisites. Building X-005's half of the work inside R-025 would not just be
scope creep; it would be building a DIFFERENT, not-yet-dispatched roadmap task
under this one's name, and Rendly's builder has no write access to Delta's ledger
(`Anoryx-EcoSystem/Delta/`) in the first place — a genuine cross-project boundary,
not just a scoping preference.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, fail-closed feature-ENTITLEMENT/GATE model: a two-tier scale, a revocable per-user entitlement record, a deterministic access check, and two concrete compositions over already-public limits in sibling modules; NOT payment collection, NOT subscription billing lifecycle, NOT any wiring to Delta)**

`src/rendly/premium.py` adds `PremiumTier` (FREE/PREMIUM), `PremiumEntitlement`
(a `bind_premium_entitlement`-constructed, optionally-expiring grant), `PremiumFeature`
(a closed two-member feature set), `has_feature_access` (the deterministic check),
and `resolve_discovery_feed_limit` / `resolve_mentorship_match_limit` — two
concrete "premium unlocks a bigger limit" compositions over R-024's
`discovery_feed.MAX_FEED_LIMIT`/`DEFAULT_FEED_LIMIT` and R-022's
`mentorship.MAX_SUGGESTIONS`/`DEFAULT_MATCH_LIMIT`, both already-public constants,
neither module modified.

Rejected: A2 (build the real subscription-billing + Delta-ledger wiring X-005
already names as separate, cross-product, not-yet-dispatched work — and which this
builder cannot make regardless: Delta's ledger lives in a different subproject
folder Rendly's builder has no write access to). Rejected: A3 (ship nothing / a
stub, treating "premium" as purely a future-UI concern). The roadmap task is real,
schedulable work — a feature-gating primitive is a genuine, honestly-buildable
gap this codebase has today (every existing B2C seam has exactly one behavior for
every user; there is no tier concept anywhere yet) — and this ADR closes it.
Rejected: A4 (an open, ops-configurable feature catalog — e.g. a table of
feature-flag rows editable at runtime). That is a real but LARGER, unrequested
feature (persisted config, an admin surface to edit it — squarely D-007/ops
territory transplanted into Rendly) this task does not invent un-asked, the same
reasoning ADR-0018 Fork A used to reject inventing "personalization" generally in
this tier.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a feature-GATE
only — no payment processor integration, no checkout/subscription lifecycle, no
Delta wiring. "Monetization (via Delta)" remains entirely unbuilt; that is X-005's
job, and X-005 remains its own, separate, still-unshipped roadmap task.

### Fork B — feature set: **B1 (a small, closed, two-member `PremiumFeature` enum, each entry backed by a concrete, already-testable composition over an existing sibling module's already-public limit constants)**

`EXTENDED_DISCOVERY_FEED` (composes R-024's feed-limit constants) and
`UNLIMITED_MENTORSHIP_MATCHES` (composes R-022's match-limit constants) were
chosen specifically because both sibling modules already export a `DEFAULT_*` /
`MAX_*` pair with no code change required to compose them — the same "import the
sibling module's already-public constant, do not modify the sibling" discipline
`discovery_feed.py` itself already established composing four OTHER modules'
outputs.

Rejected: B2 (a larger, speculative catalog of hypothetical premium perks —
"priority support", "profile boost", "read receipts", etc.). Every one of those
would be an invented, unvalidated product feature with no existing behavior to
gate in this codebase today — exactly the kind of undisclosed, unrequested
feature-invention ADR-0012/0016/0017/0018's own Fork A already rejected for this
tier's "AI"/personalization framing, applied here to "premium perks" instead.
Rejected: B3 (an open, string-keyed "any string is a feature" scheme instead of a
closed enum). Every other closed-set concept in this codebase
(`FeedItemKind`, `PrivacyField`, `ProficiencyLevel`) is a `StrEnum`, not an open
string, specifically so a caller cannot reference a feature/field/kind this
module does not know how to resolve; an open scheme would be the one
inconsistent seam in an otherwise closed-by-construction tier.

### Fork C — default when entitlement is absent or expired: **C1 (fail-closed to `PremiumTier.FREE` — mirrors `privacy.py`'s "absence means deny" default)**

`has_feature_access` treats `entitlement=None` and an entitlement whose
`expires_at` has passed as of the caller-supplied `now` identically:
`PremiumTier.FREE`, never an inferred premium grant. This is the SAME "absence is
the deny state" idiom ADR-0019/`privacy.py` already established for this
codebase's one other feature that gates rather than matches — inverted from every
OTHER opt-in record in this tier (`IntentProfile`/`CareerGoal`/
`TechStackProficiency`, where absence means "not eligible to match", not "denied")
because the honest default for a paid-tier gate is DENY, not ALLOW, exactly as
`privacy.py`'s docstring already argues for exposure grants.

Rejected: C2 (fail-open — treat a missing/expired entitlement as premium). Would
mean every caller who forgets to pass an entitlement, or every entitlement that
silently expires, grants free access to a "premium" feature — the inverse of what
"premium" is supposed to mean, and the opposite of every fail-closed precedent in
this codebase (`privacy.py`'s exposure default, D-006's kill-switch philosophy,
F-017's fail-closed JSON data-lock). Rejected: C3 (raise an error instead of
resolving to FREE when no entitlement is supplied). Every OTHER opt-in-style
function in this tier treats "no opt-in record" as a valid, expected state to
route around (`intent.py`/`career.py`/`mentorship.py`'s own "absence is the only
opted-out state" idiom) rather than an error condition; a user simply not having
paid for premium is exactly as ordinary as a user not having opted into intent
matching, and should resolve to a value (`False`/the free-tier limit), not an
exception.

### Fork D — time handling: **D1 (`now` is always caller-supplied; this module never reads the wall clock)**

Mirrors `event.py`/`event_discovery.py`'s own established discipline: every
expiry check takes `now` as an explicit keyword-only parameter, so
`has_feature_access`/`resolve_discovery_feed_limit`/`resolve_mentorship_match_limit`
are fully deterministic given their inputs and testable without patching
`datetime.now`.

Rejected: D2 (read `datetime.now(timezone.utc)` internally at the point of the
expiry check). Would make every function in this module non-deterministic and
untestable without monkeypatching — a regression from the caller-supplied-`now`
discipline this entire domain package already established.

## What is deliberately NOT built here (named, not silently skipped)

- **No payment processor integration, no checkout, no subscription-lifecycle
  flow** (no renewal, no dunning, no cancellation webhook). See Fork A/A2.
- **No wiring to Delta's ledger or budget engine.** "Monetization (via Delta)"
  remains X-005's job — a separate, still-unshipped, cross-product roadmap task
  this run did not build, and which this builder cannot reach into regardless
  (Delta's ledger is a different subproject folder).
- **No persistence for `PremiumEntitlement`.** A caller supplies it each time,
  mirroring every prior opt-in-style record in this tier — no entitlement store,
  no grant/revoke API.
- **No REST/wire surface, no UI, no pricing/plan-catalog display.** Nothing in
  `contracts/openapi.yaml` changes.
- **No open/dynamic feature catalog.** See Fork B — the feature set is a closed,
  fixed two-member enum, never a runtime-configurable list.
- **No trial period, no grace period, no proration.** An expired entitlement is
  exactly as un-premium as no entitlement at all (Fork C).

## Consequences

- Rendly's domain layer gains its first tier/entitlement primitive: a
  deterministic, fail-closed answer to "can this user use this premium feature
  right now", composable by any future caller (a future REST/UI layer, or a
  future X-005 wiring task) without that caller re-deriving the fail-closed/expiry
  logic itself.
- Two existing B2C seams (R-022's mentorship matching, R-024's discovery feed)
  now have a concrete, tested "premium unlocks a bigger limit" behavior available
  to compose, without either sibling module being modified.
- The two largest pieces of R-025's roadmap-implied scope — real payment/
  subscription handling and the actual Delta ledger wiring — remain unbuilt and
  are named here explicitly as X-005's job, exactly as R-024 named real
  candidate-pool sourcing as a future task's job rather than leaving the gap
  undocumented.
- No new attack surface is introduced: no new network endpoint, no new table, no
  new migration, no RLS change, no new identifier type, no outbound call to any
  payment processor — pure computation over caller-supplied domain objects, no
  I/O.
- The roadmap's R-025 checklist line is intentionally NOT marked "the full real
  premium/monetization vision (billing + Delta wiring + UI) shipped" — it is
  marked shipped as THIS scoped feature-entitlement seam, exactly as
  R-012/R-016/R-017/R-018/R-019/R-020/R-021/R-022/R-023/R-024 were, with the
  deferred billing/Delta-wiring/REST/UI halves named above as the obvious next
  slice (X-005).
