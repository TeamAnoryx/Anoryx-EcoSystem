# ADR-0021 — Rendly ↔ Delta Monetization Wiring Validated (X-005, non-stubbed)

- Status: Accepted
- Date: 2026-07-11
- Task: X-005 (Cross-product integration, 🏦 post-investment-tagged in the roadmap checklist;
  "Depends on: R-025, D-003") — scoped to a real emitter → Delta revenue-ingest ledger seam
  (Rendly premium grant → Delta double-entry revenue recognition). NOT a payment
  processor/checkout, NOT entitlement persistence, NOT reversal-on-revoke in v1.
- Depends on: R-025 (Rendly's pure-domain, fail-CLOSED premium feature-GATE seam `premium.py`,
  one of X-005's two named prerequisites — its ADR-0025 EXPLICITLY deferred "real money movement
  for a Rendly subscription" to X-005); D-003 (the double-entry ledger this seam posts into) and
  the Delta revenue-ingest runtime built concurrently on this same branch
  (`src/delta/ingest/router.py`'s `POST /v1/ingest/revenue`, `src/delta/ingest/posting.py`,
  `src/delta/revenue.py`, `src/delta/ingest/resolver.py`'s revenue accounts)
- Builds on: Delta ADR-0016 (X-002, Orchestrator ↔ Delta wiring validated — the SAME shape of
  proof for the sibling usage-ingest seam: drive the OTHER product's real code, POST the result
  into Delta's real app against real Postgres, assert a balanced double-entry lands); Orchestrator
  ADR-0017 (X-004, Rendly ↔ Orchestrator wiring validated — the direct precedent this test mirrors
  step-for-step, with Delta as the target instead of the Orchestrator); Rendly ADR-0028 (the
  Rendly-side design record for `monetization_emitter.py` — the Fork A–G decisions on
  scope/pricing/FREE-tier/delivery/idempotency/auth this test's real payload is built from,
  unchanged and un-re-litigated here)
- Delta-scoped numbering: this is Delta ADR **0021** — the next unused number in Delta's own
  sequence (0001–0020 assigned; 0016 also carries the X-002 sibling `0016-orchestrator-delta-
  wiring-validated.md`, so 0021 is the next free integer). Delta does not extend the
  Orchestrator's or Sentinel's global ADR sequence. The convention is "the ADR lives wherever the
  proof does": the X-005 wiring test lives in Delta's own tree (`Delta/tests/ingest/`), driving
  Rendly's code from there and POSTing into Delta's app, so the wiring-validation ADR lives here —
  exactly as ADR-0016 lives in Delta's tree for X-002 (whose test also lives in Delta's tree),
  and contrast X-004, whose ADR-0017 lives in the Orchestrator's tree because ITS test does.
- Supersedes: nothing. Adds one new test file + one CI install step; zero new tables, zero new
  migration, zero new endpoint, zero new production code (the revenue endpoint, posting, and
  contract were built by the concurrent Delta-side halves of X-005, not by this ADR).

## Context

X-005 gives Delta a cross-product monetization consume seam (`POST /v1/ingest/revenue`,
`delta-financial.schema.json`'s `RevenueIngestRecord`). Two agents built both halves of this seam
independently but concurrently on the same branch, each against the SAME Delta contract:

- **Delta** (`src/delta/ingest/` + `src/delta/revenue.py`): the real HMAC-verified ingest +
  double-entry revenue-recognition posting, proven by its own non-stubbed
  `tests/ingest/test_revenue_db.py` (real HMAC verify with the dedicated revenue secret, the
  DEBIT-receivable-ASSET / CREDIT-revenue-REVENUE posting, integer-cents, idempotency, the v1
  revoke no-op, and RLS tenant isolation) — driven by a HAND-BUILT, schema-valid revenue dict
  from the `revenue_event` conftest factory.
- **Rendly** (`src/rendly/monetization_emitter.py`): a best-effort, fail-open emitter that maps a
  real `PremiumEntitlement` → `RevenueIngestRecord` and HMAC-signs a POST, proven by its own
  non-stubbed `tests/domain/test_monetization_emitter.py` — driven against an in-process
  `httpx.MockTransport` standing in for Delta (which Rendly cannot reach in that suite; Rendly's
  own ADR-0028 names this exact gap under "What is deliberately NOT built here").

Neither suite proves the two are actually wire-compatible with EACH OTHER: that a payload Rendly's
real `build_subscription_event` genuinely produces is something Delta's real app actually accepts,
posts, and dedups. X-002 closed this identical gap for the Orchestrator→Delta usage seam and X-004
closed it for the Rendly→Orchestrator safety seam; this ADR closes it for Rendly→Delta, following
the exact same pattern.

## Decision — resolved forks (mirrors ADR-0016 / ADR-0017's fork-table shape)

| Fork | Decision |
|------|----------|
| **A** — how to obtain a "genuine" Rendly revenue event without a live Rendly deployment | **A1**: drive Rendly's REAL, installed domain + emitter code in-process — a real `Profile`, a real `bind_premium_entitlement` grant, then `monetization_emitter.build_subscription_event` (the exact PURE function `emit_subscription_event` calls in production to build the wire body before its fire-and-forget POST) — imported unmodified from the installed `rendly` package the `ledger-db` CI lane now installs (`pip install -e "../Rendly[dev]"`). Nothing about the payload shape is hand-typed by the test; the point is proving Rendly's REAL output is Delta-compatible. |
| **B** — importing a "private-but-pure" cross-product function | **B1**: `build_subscription_event` is Rendly's PUBLIC pure mapper (not `_`-prefixed), so no privacy question even arises here — a strictly cleaner case than X-001/X-004, which imported a private-but-pure `_stamp_event`/`_build_payload`. Driving the pure mapper directly (rather than the async, env-gated, fire-and-forget `emit_subscription_event`) is the only way to get the real payload shape without either duplicating that logic by hand (drift risk) or fighting Rendly's deliberate fail-open delivery design (ADR-0028 Fork E — the emitter no-ops when its env is unset and swallows every transport outcome; awaiting it here would validate nothing about the wire compatibility this ADR is about). |
| **C** — which cases to cover | **C1**: the PREMIUM grant happy-path (accept + balanced double-entry + integer-cents), a byte-identical replay (idempotency), the FREE-tier boundary (`build_subscription_event` returns `None` → nothing to POST → the "FREE bills nothing" seam), and the `subscription_revoked` v1 no-op (durable-accept, posts nothing). This covers every branch of Rendly's real mapper AND every disposition of Delta's real revenue route without duplicating the depth `test_revenue_db.py` already owns (forgery, DLQ, RLS depth). |
| **D** — auth / source identity | **D1**: real HMAC over `f"{timestamp}.{body}"` (`sha256=` hex prefix, `X-Orchestrator-Signature`/`X-Orchestrator-Timestamp`, ±300s window) keyed by the DEDICATED revenue secret (`DELTA_REVENUE_INGEST_HMAC_SECRET`, distinct from the usage secret), reusing the conftest `sign_revenue` helper. `source_product` is server-resolved to `rendly` from the authenticated key, never read from the body — the test asserts Rendly's real payload never includes a `source_product` key (nor `currency`, which Delta defaults), exactly the boundary X-004 confirmed for its bearer seam. |
| **E** — scope boundary (what this does NOT re-prove) | **E1**: this suite does not re-drive Rendly's own async `emit_subscription_event` delivery / env-gating / exception-swallowing path (`Rendly/tests/domain/test_monetization_emitter.py` already proves that in-product against a MockTransport) or Delta's own posting internals beyond the round trip (`Delta/tests/ingest/test_revenue_db.py` already proves forgery rejection, the usage-secret-is-not-the-revenue-secret boundary, DLQ, and RLS depth). Re-proving either here would duplicate coverage without validating anything new about the *wiring*. |

## The revenue-recognition posting model (and why it is the honest double-entry)

A `subscription_granted` event posts ONE balanced two-leg transaction:

    DEBIT   <subscription_receivable  ASSET>     amount_cents
    CREDIT  <subscription_revenue     REVENUE>   amount_cents      (nets to zero)

This is the honest double-entry for *recognizing* subscription revenue at this seam. The credit
increases a REVENUE account — recognized subscription income. The debit increases an ASSET
account (a receivable) rather than cash, because **this seam records that revenue was recognized;
it does not record that money was collected.** Rendly's emitter forwards a grant that has already
been decided elsewhere (ADR-0028 Fork A) — there is no payment processor, no cash movement, no
settlement in X-005. Debiting a `subscription_receivable` asset (an amount owed to / to be
collected by the tenant) rather than a cash/bank account is precisely what keeps the ledger honest
about that: the transaction asserts "revenue recognized, consideration receivable," not "cash
received." A future payment-collection layer (still deferred, see below) would post the *separate*
settlement leg (DEBIT cash / CREDIT receivable) that clears this receivable. The transaction is
balanced by construction (`Σdebit == Σcredit`, re-checked by the D-003 deferred trigger at COMMIT).

Supporting invariants the wire proof exercises end-to-end:

- **Integer-cents enforcement.** `amount_cents` is validated as a TRUE `int` (float/bool/str
  rejected, never routed through the float-accepting `Money.from_wire_cents`) and bounded to the
  Money ceiling — money is never a float in Delta. The test reads `amount_minor_units` back from
  the ledger and asserts `type(...) is int` and both legs `== 1499` (the PREMIUM static-placeholder
  price Rendly's real `_TIER_PRICE_CENTS` stamps).
- **Dedicated per-source HMAC secret trust boundary.** The revenue seam authenticates ONLY against
  `DELTA_REVENUE_INGEST_HMAC_SECRET`, distinct from the usage seam's `DELTA_INGEST_HMAC_SECRET`.
  Because v1 accepts exactly one source product, holding THIS secret === being Rendly, so
  `source_product` is server-resolved in code and never read from the body. A leak of one seam's
  secret never authenticates the other (proven separately by `test_revenue_db.py`'s
  usage-secret-rejection vector).
- **Idempotency namespacing.** The ledger idempotency key is namespaced `revenue:rendly:{key}`
  over Rendly's deterministic uuid5 key (`rendly-sub-…`, derived from grant identity + event_type,
  ADR-0028 Fork F), so a retry reproduces the same key and Delta dedups it as an idempotent replay
  (never a second transaction) — and it can never collide with a usage event's `event_id` in the
  ledger's `(tenant_id, idempotency_key)` partial-unique index.

## What this proves (and what it doesn't)

**Proves:** a genuinely Rendly-produced `RevenueIngestRecord` — real `Profile` → real
`bind_premium_entitlement` → real `build_subscription_event`, real dedicated-secret HMAC auth — is
accepted end-to-end by Delta's real `POST /v1/ingest/revenue`, posts EXACTLY one balanced
revenue-recognition transaction (DEBIT receivable ASSET / CREDIT revenue REVENUE, both
`amount_cents == 1499`, integer, balanced) durably in that tenant's RLS-scoped ledger, and is
correctly deduplicated (`applied=false`, `idempotent_replay=true`, no second row) on a
byte-identical replay carrying Rendly's own deterministic idempotency key. It also proves the two
boundaries at the wiring level: a FREE-tier grant produces NO event (`build_subscription_event`
returns `None` → nothing to POST → empty ledger), and a `subscription_revoked` grant is durably
accepted (`applied=false`) but posts nothing.

**Does not prove (honesty boundary, non-removable):** that Rendly's live deployment today actually
calls Delta in production (it does not — per ADR-0028, `RENDLY_DELTA_REVENUE_INGEST_URL`/
`RENDLY_DELTA_REVENUE_HMAC_SECRET` are unconfigured in every deployment, a deliberate safe no-op
default); that Rendly's own async fire-and-forget scheduling / timeout / exception-swallowing
works (Rendly's own suite proves that — this test calls the pure `build_subscription_event`
directly, never `emit_subscription_event`); mTLS peer authentication (deferred across every
X-family wiring ADR to O-008, same boundary as ADR-0016 §"Does not prove" — until then the HMAC
secret-holder is the authenticated peer); Delta's own DLQ / forgery-rejection / RLS depth (proven
in `test_revenue_db.py`, not re-proven here).

## DEFERRED scope (verbatim, non-removable)

The following are OUT of X-005 v1 and are named here, not silently implied away (mirroring
Rendly ADR-0028's "What is deliberately NOT built here" and R-025 ADR-0025's honesty boundary):

- **No payment processor / checkout flow.** Nothing here collects money; the seam forwards a grant
  ALREADY decided elsewhere and recognizes revenue against a *receivable*. Real payment collection
  remains deferred exactly as R-025 (ADR-0025) left it — this is still R-025's stated exclusion.
- **No entitlement persistence.** There is no grant/revoke table, no delivery ledger, no outbox on
  either side; a caller supplies the entitlement each time (R-025's / ADR-0028's no-persistence
  discipline).
- **No reversal-on-revoke in v1.** Rendly emits `subscription_revoked` and Delta durably RECORDS
  it, but Delta does NOT reverse or void the granting transaction in v1. Automatic
  revocation/reversal posting (the settlement/clearing leg) is a Delta-side deferred follow-up.
- **Static placeholder pricing (not a plan catalog).** The per-tier price is a single hard-coded
  integer-cents list price (`PREMIUM = 1499`), honestly labelled a placeholder. Dynamic pricing,
  per-tenant negotiated rates, and a pricing source of record / plan catalog are a genuinely larger
  unrequested feature, deferred (ADR-0028 Fork C).
- **Fail-open best-effort delivery (a lost revenue event is possible).** Rendly's emitter is
  fail-open: a delivery failure is swallowed, never raised, never retried, so a lost revenue event
  is an accepted risk at this WIRING seam (Delta's ledger, not the emitter, is the system of
  record). Reliable/guaranteed delivery (an outbox + retry + DLQ, or an at-least-once worker) is
  DEFERRED — and, because the idempotency key is deterministic, it is strictly additive (a future
  outbox re-drives the SAME `build_subscription_event` output without risking a double-post). See
  ADR-0028 Fork E for the full reliability caveat.

## Testing

`Delta/tests/ingest/test_rendly_revenue_wiring_e2e.py` (module-level `skipif` on the Delta DB env,
mirroring `test_revenue_db.py` — the same gate the sibling revenue-DB suite already uses; no new
`DELTA_REQUIRE_*` flag, since this proves an existing seam's cross-repo compatibility rather than
gating a new autonomous behavior, same reasoning as ADR-0016 / ADR-0017):

- `test_real_rendly_premium_grant_posts_balanced_revenue_and_is_idempotent` — accept, one balanced
  DEBIT-asset / CREDIT-revenue transaction at `amount_cents == 1499` (integer), and a
  byte-identical replay dedups (no second row).
- `test_free_tier_entitlement_produces_no_event_so_nothing_is_billed` — a real FREE-tier grant →
  `build_subscription_event` returns `None` → nothing to POST → empty ledger.
- `test_real_rendly_subscription_revoked_accepts_but_posts_nothing` — a real `subscription_revoked`
  grant → 200 `applied=false`, no ledger entries, no transaction.

Verified locally against a real Postgres 16 instance (CI's exact `ledger-db` env / role / migration
setup — `alembic upgrade head`, `delta_app` SCRAM-provisioned, `DELTA_PROVISION_APP_ROLE=1`, with
Delta's AND Rendly's `[dev]` extras installed under Python 3.12): the new file passes all three
cases in isolation (`3 passed`), the full `tests/ingest` package passes (`72 passed, 1 skipped` —
the ORCH-gated `test_seam_e2e.py`), and the full Delta suite passes with it included (`927 passed,
15 skipped`). `ruff check .` and `black --check .` — both clean.

## Out of scope (do not build here)

Rendly's live production wiring to a real Delta deployment (deferred per ADR-0028, unaffected by
this ADR); Rendly's own fail-open delivery / scheduling coverage (Rendly's own suite); a payment
processor / checkout / settlement leg (still deferred, R-025 / ADR-0025); reversal-on-revoke
posting (Delta-side deferred follow-up); a dynamic pricing source / plan catalog (ADR-0028 Fork C);
reliable-delivery infrastructure (ADR-0028 Fork E); mTLS peer provisioning (O-008); any change to
`Anoryx-Sentinel/contracts/`, `policy.schema.json`, or Rendly's `monetization_emitter.py` runtime
(this ADR only imports already-shipped Rendly code and adds one Delta test + one CI step).

## Consequences

- X-005 is proven, not merely asserted: the roadmap's Rendly↔Delta monetization seam closes with a
  concrete, non-stubbed demonstration that Rendly's real emitted `RevenueIngestRecord` and real
  dedicated-secret HMAC auth are wire-compatible with Delta's real revenue-recognition ingestion —
  mirroring the X-002 (Orchestrator↔Delta) and X-004 (Rendly↔Orchestrator) precedents.
- The Delta CI `ledger-db` lane now installs `rendly` editable alongside Delta so this cross-repo
  proof executes on every relevant PR (the banked "gate new test lanes in CI — verified to execute,
  not skip" lesson): the new file self-skips absent the DB env in the no-DB `quality` lane, and
  runs for real in `ledger-db`.
- The financial through-line is now demonstrably wire-verified end to end for its revenue leg:
  Rendly premium grant → Delta double-entry revenue recognition, keyed by a dedicated per-source
  secret, integer-cents, idempotent — with the deferred boundaries (collection, persistence,
  reversal, dynamic pricing, reliable delivery) named and unremoved.
