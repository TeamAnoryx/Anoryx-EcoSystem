# ADR-0028 — Rendly → Delta Monetization Emitter: forwarding a real premium grant to Delta's revenue ledger (X-005, Rendly side)

Status: Accepted
Date: 2026-07-11
Builds on: ADR-0025 (R-025 — the pure-domain, fail-CLOSED premium feature-GATE seam
`premium.py`; its honesty boundary EXPLICITLY deferred "real money movement for a Rendly
subscription" to X-005, i.e. THIS task), ADR-0026 (X-004 — `realtime/safety_event_emitter.py`,
the best-effort/fail-open cross-product emitter whose structure, error-handling, and test style
this module mirrors), `Delta/contracts/delta-financial.schema.json` (`RevenueIngestRecord` /
`POST /v1/ingest/revenue` — the Delta-owned wire contract this conforms to and NEVER edits; a
different subproject this builder has no write access to). In spirit: Anoryx-Sentinel ADR-0023
(F-020 Fork E / D5 — "a delivery failure NEVER touches the request path," the fail-open precedent
X-004 already replicated for Rendly and this ADR replicates again).

## Context

The roadmap names `X-005 — Rendly ↔ Delta monetization wiring 🏦, "Depends on: R-025, D-003"`.
R-025 (shipped) built one of its two named prerequisites: a pure-domain, fail-closed feature-GATE
model (`PremiumTier`, a revocable `PremiumEntitlement`, `has_feature_access`), and its ADR-0025
honesty boundary said, verbatim: *"Real money movement for a Rendly subscription is its own,
separate, still-unshipped cross-product task (X-005)."* Delta's side (D-003 ledger + the
`POST /v1/ingest/revenue` endpoint and its `RevenueIngestRecord` contract) is finalized and owned
by the Delta subproject. This task builds the **Rendly-side half of X-005 only**: the emitter that
maps a real `PremiumEntitlement` → Delta's `RevenueIngestRecord` and forwards it, so a genuine
premium grant (or revocation) lands as a monetization event in Delta's ledger.

Scope discipline (the same boundary R-025 held, now held from the other side): this task builds
exactly ONE thing — the emitter. It does NOT build the payment/checkout/subscription-lifecycle
flow, entitlement persistence, or a REST surface that R-025 deferred; those remain deferred and are
named explicitly below. It never writes into `Delta/**` — it conforms to Delta's contract as a
client, exactly as X-004 conformed to the Orchestrator's `SafetyEventIngestRequest`.

## Decisions (one per resolved fork)

### Fork A — scope: **A1 (emitter ONLY — a pure mapper + a best-effort POST; NO payment processor, NO checkout/subscription lifecycle, NO entitlement persistence, NO REST surface)**
`src/rendly/monetization_emitter.py` adds a PURE `build_subscription_event(entitlement, *,
event_type, occurred_at) -> dict | None` (real `PremiumEntitlement` → schema-valid
`RevenueIngestRecord`) and an async, best-effort `emit_subscription_event(...)` that HMAC-signs and
POSTs it. That is the whole surface. Rejected: A2 (build the payment/checkout/billing-lifecycle
flow here) — that is the OTHER, still-deferred half of R-025's roadmap-implied scope; R-025 named
it deferred, and nothing about "wire a grant to the ledger" requires collecting money. Rejected: A3
(persist grants/emitted events in a Rendly table / outbox) — R-025 deliberately shipped NO
persistence (a caller supplies the entitlement each time); adding a store here would widen scope
into exactly the persistence R-025 declined. Rejected: A4 (expose a Rendly REST endpoint for
grant/revoke) — no wire surface was asked for; `contracts/openapi.yaml` is unchanged.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is the monetization EMITTER only —
a mapper + a best-effort signed POST. It is NOT a payment processor, NOT a checkout, NOT a
subscription-billing lifecycle, and NOT an entitlement store. It forwards a grant that has ALREADY
been decided elsewhere; it does not decide, collect, or persist one. Real payment collection and
entitlement persistence remain deferred, exactly as R-025 left them.

### Fork B — module placement: **B1 (top-level `rendly/monetization_emitter.py`, tests in `tests/domain/`)**
X-004's emitter lives under `realtime/` because it is realtime-pipeline-adjacent (called from the
chat send path). This emitter is **premium-adjacent**: it imports `premium.py` (top-level) and maps
a `PremiumEntitlement`, with no realtime coupling. So it lives top-level next to `premium.py`, and
its tests live in `tests/domain/` next to `test_premium.py`. This placement is also what keeps its
coverage honest: top-level `rendly/*` is measured by the no-DB contracts lane's `fail_under=90`
gate (the module reaches 100%), whereas `realtime/*` is omitted from that lane (measured only in
the DB lane). Rejected: B2 (put it under `realtime/` beside the safety emitter) — it has no
realtime dependency, and it would then escape the no-DB coverage gate despite being pure/no-DB.

### Fork C — pricing source: **C1 (a STATIC placeholder per-tier list price in integer cents)**
`_TIER_PRICE_CENTS = {PremiumTier.PREMIUM: 1499}` — a single hard-coded $14.99/mo list price, in
INTEGER cents (never a float; this is Delta, where money is integer minor units). `PremiumTier.FREE`
has NO entry: a free entitlement is not a monetization event, so `build_subscription_event` returns
`None` for it and the emitter sends nothing. Rejected: C2 (a dynamic pricing service / plan catalog
lookup) — dynamic pricing, per-tenant negotiated rates, and a plan catalog are a genuinely larger,
unrequested feature (a pricing source of record, an admin surface to edit it) that X-005 does not
invent; the static price is honestly labelled a placeholder list price in both code comment and
this ADR, and a real pricing source is named as deferred below.

### Fork D — FREE tier: **D1 (a FREE entitlement produces NO revenue event)**
There is nothing to bill for a free grant, so both `build_subscription_event` (returns `None`) and
`emit_subscription_event` (no-op) refuse to emit for `PremiumTier.FREE`. This is symmetric with
R-025's fail-closed gate: FREE is the un-monetized state on both the access side (no premium
feature) and the revenue side (no ledger event). Rejected: D2 (emit a zero-amount event for FREE) —
a `amount_cents: 0` revenue record is a misleading ledger entry (it asserts a $0 subscription
transaction happened when none did); absence is the honest representation of "not billable."

### Fork E — delivery model: **E1 (best-effort, FAIL-OPEN, fire-and-forget — no retry/outbox/DLQ)**
`emit_subscription_event` reads its config from env, and if either `RENDLY_DELTA_REVENUE_INGEST_URL`
or `RENDLY_DELTA_REVENUE_HMAC_SECRET` is unset it is a silent no-op (mirrors `realtime/ice.py`'s
degrade-not-block and X-004's unconfigured no-op). When configured, it awaits one bounded (3s)
HMAC-signed POST and swallows EVERY transport / non-2xx outcome (logged, never raised, never
retried) — the same fail-open posture X-004 documents (ADR-0026 Fork E / ADR-0023 Fork E).

**This is the one fork where reliability deserves an honest caveat.** A lost oversight notification
(X-004) is plainly acceptable; a lost REVENUE event is more consequential. The decision to still
ship fail-open best-effort here rests on three specific properties, not on treating revenue as
cheap:
  1. **Delta's ledger — not this emitter — is the system of record.** This seam is monetization
     WIRING at an oversight/integration boundary; it is not the authoritative billing path.
  2. **The payload is idempotent on retry.** The idempotency key (Fork F) is deterministic per
     (grant identity + event_type), so a future reliable-delivery layer (an outbox that re-drives
     the SAME `build_subscription_event` output) can be added WITHOUT changing this module's shape
     or risking double-posting in Delta.
  3. **Coupling a grant to Delta's uptime is the worse failure.** Awaiting-and-raising would let a
     Delta outage break the grant path itself — the exact "delivery failure touches the request
     path" anti-pattern ADR-0023 forbids.

Because (2) makes reliable delivery a strictly additive future layer, **guaranteed/reliable
delivery (an outbox + retry + DLQ, or an at-least-once worker) is named as DEFERRED here, not
implied away** — a later X-005 follow-up should add it if revenue-event completeness becomes
load-bearing rather than best-effort. Rejected: E2 (await-and-raise so a failed POST fails the
caller) — violates the request-path-isolation precedent and couples grants to Delta's uptime.
Rejected: E3 (build the outbox/worker NOW) — real infrastructure Rendly does not have (X-004 made
the same call for the same reason); deferred, not silently skipped.

### Fork F — idempotency key: **F1 (DETERMINISTIC uuid5 over grant identity + event_type)**
`idempotency_key = "rendly-sub-" + uuid5(NS, f"{tenant_id}:{user_id}:{tier}:{granted_at}:{event_type}")`.
Derived from the entitlement's identity (`tenant_id`, `user_id`, `tier`, `granted_at`) plus
`event_type` — NOT from `occurred_at` (the wall-clock send time), so re-emitting the SAME grant
(e.g. a retry, or the future outbox of Fork E) reproduces the EXACT same key and Delta dedups it as
an idempotent replay (never a second ledger transaction), while a different `event_type`
(grant vs revoke) or a different `tier`/grant yields a different key. The result — a fixed prefix
plus a dashed uuid5 hex — satisfies Delta's `^[A-Za-z0-9._:-]{1,128}$` pattern and is ~47 chars,
well under 128. Rejected: F2 (a random uuid4 per call) — a retry would mint a NEW key and Delta
would post a DUPLICATE ledger transaction; the deterministic key is what makes Fork E's fail-open
posture safe.

### Fork G — auth: **G1 (replicate Delta's existing inbound-ingest HMAC convention exactly)**
Delta's `RevenueIngestRecord` contract specifies HMAC-SHA256 over the literal bytes
`f"{timestamp}.{body}"`, sent as `X-Orchestrator-Signature: sha256=<hexdigest>` /
`X-Orchestrator-Timestamp: <unix-seconds>`, with a ±300s replay window and a dedicated per-source
secret (`DELTA_REVENUE_INGEST_HMAC_SECRET` on Delta's side) that IDENTIFIES the source product —
which is why `source_product` is server-resolved and MUST NOT appear in the body. This module reads
its own copy of that shared secret from `RENDLY_DELTA_REVENUE_HMAC_SECRET`, signs the EXACT body
bytes it POSTs (so Delta's verify over the raw received body matches regardless of key ordering),
and omits `source_product` and `currency` (Delta applies its default currency) from the body. This
mirrors X-004's discipline (`source_product`/`category` server-resolved from the credential, closed
body shape) and the Orchestrator→Delta usage-ingest seam it descends from.

## What's built

- `src/rendly/monetization_emitter.py` (new) — `build_subscription_event` (pure mapper,
  `PremiumEntitlement` → `RevenueIngestRecord | None`), `_idempotency_key` (deterministic uuid5),
  `emit_subscription_event` (async, env-gated, best-effort, fail-open), `_post_event` (the bounded,
  HMAC-signed, exception-swallowing POST). Reads `RENDLY_DELTA_REVENUE_INGEST_URL` and
  `RENDLY_DELTA_REVENUE_HMAC_SECRET`; uses `httpx` (already a core runtime dep since X-004).
- `tests/domain/test_monetization_emitter.py` (new) — payload-shape/pattern correctness, the
  FREE-tier `None`, idempotency-key stability/discrimination, the unconfigured no-op (each env var
  individually and together), fail-open swallowing of a non-2xx and a transport exception, and an
  HMAC round-trip that re-validates the signed request. `httpx.MockTransport`, mirroring
  X-004's test style (no real socket, a genuine httpx round-trip).
- `premium.py` — UNCHANGED. This module imports `PremiumEntitlement`/`PremiumTier` read-only; no
  additive export was needed, and no R-025 signature was touched.

## The example payload this emitter produces

For a PREMIUM grant of tenant `12121212-…`, user `11111111-…`, `granted_at` /
`occurred_at` `2026-07-10T12:00:00+00:00`:

```json
{
  "tenant_id": "12121212-1212-4212-8212-121212121212",
  "event_type": "subscription_granted",
  "tier": "premium",
  "amount_cents": 1499,
  "idempotency_key": "rendly-sub-<deterministic-uuid5-hex>",
  "occurred_at": "2026-07-10T12:00:00+00:00"
}
```

No `currency` (Delta defaults it), no `source_product` (Delta resolves it from the HMAC key). A
FREE-tier entitlement produces `null` (no event). `subscription_revoked` produces the same shape
with `event_type: "subscription_revoked"` and a distinct `idempotency_key`.

## What is deliberately NOT built here (named, not silently skipped)

- **No payment processor / checkout / subscription-lifecycle flow** (no Stripe, no invoice, no
  renewal/dunning/proration). Still deferred, exactly as R-025 deferred it (Fork A).
- **No entitlement persistence and no delivery ledger/outbox.** A caller supplies the entitlement
  each time; nothing here stores grants or emitted events (Fork A).
- **No REST/wire surface of Rendly's own.** `contracts/openapi.yaml` is unchanged (Fork A).
- **No dynamic pricing / plan catalog.** The per-tier price is a static placeholder list price;
  a real pricing source of record is a later task (Fork C).
- **No guaranteed/reliable delivery (retry, backoff, outbox, DLQ).** Delivery is fail-open
  best-effort; a reliable-delivery layer is deferred and is strictly additive thanks to the
  deterministic idempotency key (Fork E).
- **No revocation REVERSAL semantics.** Rendly emits `subscription_revoked`, but per Delta's
  documented v1 behavior (`RevenueEventType` in `delta-financial.schema.json`) Delta *records* a
  revoke and does NOT reverse or void the granting transaction in v1 — automatic
  revocation/reversal posting is a Delta-side deferred follow-up. This emitter forwards the event;
  it makes no claim that a revoke undoes a grant.
- **The genuine two-app e2e** (real Rendly emitter → real Delta `POST /v1/ingest/revenue` running
  together) — a SEPARATE task another builder owns; this task's tests are Rendly-local unit/contract
  coverage against an in-process `httpx.MockTransport`, exactly as X-004 stood in for the
  concurrently-built Orchestrator runtime.

## Consequences

- A real Rendly premium grant/revocation can now be forwarded to Delta's revenue ledger as a
  schema-conforming, HMAC-signed `RevenueIngestRecord`, closing the Rendly half of X-005 — with
  R-025's fail-closed gate and X-005's fail-open emitter kept as two clearly separate postures
  (one gates access, the other forwards a monetization event; a delivery failure never touches a
  grant).
- Every existing R-025 behavior is provably unchanged: `premium.py` is untouched and
  `tests/domain/test_premium.py` passes unmodified.
- A Rendly deployment that never sets `RENDLY_DELTA_REVENUE_INGEST_URL` /
  `RENDLY_DELTA_REVENUE_HMAC_SECRET` (every deployment today, since Delta connectivity is not wired
  up) behaves exactly as before — the seam is additive and fully optional.
- No new attack surface of note: one bounded outbound HMAC-signed POST to a single configured
  endpoint, no new inbound endpoint, no new table, no new identifier type. The static price and the
  deterministic key are pure computation over a caller-supplied domain object.
```
