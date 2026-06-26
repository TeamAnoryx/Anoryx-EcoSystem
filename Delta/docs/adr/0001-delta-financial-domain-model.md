# ADR-0001 — Delta Financial Domain Model

- **Status:** Proposed (awaiting Affu approval)
- **Date:** 2026-06-26
- **Task:** D-001 (first Delta task)
- **Scope:** Canonical financial domain *model* — types, JSON Schemas, and
  integrity invariants. **No engine, no DDL.**
- **Depends on:** shipped F-001 (identity model, `contracts/ids.md`).
- **Numbering:** Delta-scoped sequence (this is Delta ADR **0001**), mirroring how
  Anoryx-Sentinel keeps its ADRs inside its own subtree
  (`Anoryx-Sentinel/docs/adr/`, head 0024). Delta does not extend Sentinel's
  global sequence (decision D6).

---

## Context

Delta is the FinOps / ERP / budget-policy product. The ecosystem's defining
feature is *financial policy enforced in the security path*:

```
Sentinel → (usage/cost events) → Anoryx-AI-Orchestrator → Delta
Delta → (budget policies) → Anoryx-AI-Orchestrator → (enforcement) → Sentinel
```

That loop cannot be built until Delta has a **canonical financial vocabulary** and
the **integrity invariants** that keep it sound: accounts, ledger entries,
transactions, cost centers, projects, allocations, budget concepts, usage records,
time windows, and burn-rate. Every later Delta task (the ledger engine D-003, the
budget engine D-005, and onward) inherits the vocabulary and invariants fixed
here. This ADR therefore sets the financial language for the whole product, and it
**must not contradict the LOCKED** `Anoryx-Sentinel/contracts/policy.schema.json`
(frozen at F-008 `a9e2344`) — that schema is the integration contract D-002 will
emit into and it cannot move.

This ADR records decisions; the build (D-001 STEP 2–6) implements them as Pydantic
v2 types, hand-written JSON Schemas, and real validators with tests.

---

## Decision

### Fork 1 — Attribution model: **(a) cost center ≡ Sentinel `team_id`**

Every cost is attributed to the four Sentinel stable IDs exactly as they arrive on
events: `(tenant_id, team_id, project_id, agent_id)`. A "cost center" in Delta
**is** a Sentinel `team_id`; a "project" **is** a Sentinel `project_id`. No
Delta-native department/org-tree is introduced now.

*Why:* `UsageEvent` (`contracts/events.schema.json`) carries exactly these four
IDs and no department dimension — so (a) is **lossless** (nothing to drop or
synthesize), rollups are a `GROUP BY` on four indexed columns, the RLS shape is
the F-003b `tenant_id` column verbatim, and the LOCKED Budget variant's `scope`
enum (`tenant|team|project|agent`) maps **1:1**. A native org hierarchy (option b)
would force a lossy Delta-scope → Sentinel-ID translation, add tables that each
need their own RLS, and enlarge the D-003 migration — all before any consumer
needs it (YAGNI). A department/org-tree overlay can be added later (D-013+
Enterprise-OS) as a *mapping view over* these flat attribution columns, with no
reshape of the cost records.

### Fork 2 — Money representation: **integer minor units (integer cents)**

Money is `(minor_units: int, currency)`. The minor unit is **cents**, chosen to
match both wire fields that denominate money in cents
(`max_cost_cents_per_period`, `cost_estimate_cents`). **Floats are forbidden in
every monetary field** — a validator rejects `float`, `bool`, `NaN`, and
`Infinity`. Values are stored as Python `int` (arbitrary precision → no silent
native overflow) and **validated against the wire maxima** so a Delta value can
never exceed what the contract can carry:

- cost: `0 ≤ minor_units ≤ 100_000_000_000` (1e11 cents, the Budget max)
- tokens: `0 ≤ n ≤ 1_000_000_000_000` (1e12, the Budget max)

The wire `cost_estimate_cents` is a JSON `number` (sub-cent fractions possible).
Delta **quantizes half-even to integer cents at ingest** and records the integer.
This is an honest, documented loss: the figure is a *client-side cost estimate*,
not an authoritative bill, so sub-cent precision is not meaningful. `Decimal` was
considered (preserves sub-cent fidelity) but adds context handling and serializes
awkwardly into the `number` wire field for no consumer benefit.

### Fork 3 — Cost source: **Delta RECORDS Sentinel's cost**

Delta does not own a pricing table and does not recompute cost. It records the
cost Sentinel already computed at stream time (F-006), carried on
`UsageEvent.cost_estimate_cents`. `Delta.UsageRecord` therefore mirrors
`UsageEvent`:

```
UsageRecord = {
  tenant_id, team_id, project_id, agent_id,   # attribution (Fork 1a)
  model,                                       # end-user model name
  tokens_in: int, tokens_out: int,
  cost_estimate_cents: int,                    # quantized from wire number (Fork 2)
  currency,                                    # ISO-4217 tag (Fork 4)
  request_id, event_id, event_timestamp        # join keys back to the event
}
```

Single source of truth, no divergence between Delta and Sentinel cost figures, no
pricing logic to maintain. Honest label everywhere: *client-side cost estimate*.

### Fork 4 — Currency: **single currency, ISO-4217 tagged, no FX**

Every monetary value carries an ISO-4217 currency code (default `USD`). D-001 never
converts between currencies and ships no FX/rate table. Any operation that must net
amounts — a balanced `Transaction`, a reconciled `Allocation` — **rejects** a set
whose entries mix currencies (you cannot net `USD` against `EUR` without a rate,
and inventing one silently would be dishonest). Multi-currency + FX is deferred
until a consumer needs it.

### Fork 5 — Schema authority / builder seam: **defer ledger DDL to D-003**

D-001 ships Pydantic types + JSON Schemas + the invariant/reconciliation spec +
this ADR + tests. It emits **no Alembic migration and no `.sql`**. The
authoritative ledger schema is D-003's to own; D-001 only fixes the *shape* the
DDL must take. This keeps the api-architect↔persistence split clean and honours the
D-001 DO-NOT-MERGE rule "no DDL/migrations added." Any illustrative DDL that
appears in docs is labelled **NON-AUTHORITATIVE reference**. The tenant-first
shaping plus the RLS handoff note below is the guidance D-003 builds from.

### D6 — ADR scoping: **Delta-scoped**

This ADR lives at `Delta/docs/adr/0001-...`; the D-001 security audit lives at
`Delta/docs/audit/d-001-security-audit.md`. Delta keeps its own decision record,
matching the established pattern that each product subtree is self-describing.

---

## The double-entry account abstraction + the balanced-entry invariant

Delta's ledger vocabulary is classical double-entry:

- **`Account`** — `account_id`, `tenant_id`, `type ∈ {asset, liability, equity,
  revenue, expense}`, `currency`, `name`. Immutable (frozen).
- **`LedgerEntry`** — `entry_id`, `tenant_id`, `account_id`, `direction ∈ {debit,
  credit}`, `amount: Money` (non-negative minor units), attribution (`team_id`,
  `project_id`, `agent_id`), `timestamp`. Immutable.
- **`Transaction`** — `txn_id`, `tenant_id`, `entries: list[LedgerEntry]` (≥ 2),
  `timestamp`, `description`. Immutable.

**Balanced-entry invariant (the rule that defines a sound ledger):** a
`Transaction` is valid only if

1. `Σ(debit amounts) == Σ(credit amounts)` (the books balance), **and**
2. every entry shares one `currency` (Fork 4 — no silent cross-currency netting),
   **and**
3. every entry's `tenant_id` equals the transaction's `tenant_id` (no cross-tenant
   transaction).

The invariant is enforced by a Pydantic `@model_validator` that runs on
construction; because the type is **frozen**, **no normal construction or
mutation path can produce or mutate an unbalanced, mixed-currency, or
cross-tenant `Transaction`** — construction either yields a balanced transaction
or raises `ValidationError`. (Pydantic's `model_construct()` deliberately skips
validation; it is a documented escape hatch, not a supported path, and is called
out as such in the `Transaction` docstring.) This is the integrity guarantee
D-003's ledger engine will rely on.

---

## Reconciliation rules

Reconciliation is expressed as validators/spec in D-001 (the *engine* that runs
them continuously is D-003/D-005):

- **Allocation consistency:** an `Allocation`'s declared total equals the sum of
  its distributed target amounts (`Σ targets == total`); a mismatch is flagged.
  Targets must share the allocation's currency.
- **Trial balance:** across a set of balanced transactions, total debits equal
  total credits (a corollary of the per-transaction invariant; used to detect a
  malformed *set*).
- **Tenant + currency consistency:** every entry in a transaction shares the one
  `tenant_id` and one `currency` (same as invariant clauses 2–3, surfaced as a
  reconciliation check for set-level callers).

---

## Burn-rate as a derivation (never stored)

Burn-rate is a **pure function** over a time-series, never a stored field on any
type:

```
burn_rate(records, window: TimeWindow) -> {cost_cents_per_unit_time, tokens_per_unit_time}
```

It sums cost/tokens of the records whose timestamp falls in `window` and divides by
the window duration. Because it is always recomputed from the underlying
records/ledger, it **cannot desync** from the source of truth — there is no
duplicated, mutable burn-rate number to forge or let drift. `TimeWindow`
(`start`, `end`, `granularity`) bounds the derivation.

---

## Attribution → Sentinel-ID mapping; tenant-first / RLS-ready design (D-003 handoff)

Every tenant-scoped type carries a required `tenant_id` as its first attribution
field, and cost-bearing types additionally carry `team_id`, `project_id`,
`agent_id` with the **exact formats from the contracts**: tenant/team/project are
UUID strings (`maxLength 64`), `agent_id` is the lowercase slug
`^[a-z0-9]+(-[a-z0-9]+)*$`. This is the same shape Sentinel attributes events with,
so the join key between a Sentinel event and a Delta record is the four IDs +
`request_id`/`event_id`.

**Handoff note for D-003 (RLS):** when D-003 writes the authoritative ledger DDL,
every tenant-scoped table maps one Pydantic type → one table with a `tenant_id`
column, and applies the F-003b Option α policy verbatim (fail-closed, USING +
WITH CHECK):

```sql
ENABLE ROW LEVEL SECURITY;
FORCE ROW LEVEL SECURITY;
-- both USING and WITH CHECK:
tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
```

served through the `sentinel_app`-style NOBYPASSRLS role and a
`get_tenant_session(tenant_id)` helper that sets the transaction-local GUC and
autobegins. Because every D-001 type is already tenant-first, **no reshape is
needed** to apply RLS — the model and the isolation boundary agree by
construction.

---

## Budget-variant compatibility (CONFIRM — verified, schema stays frozen)

`Delta.BudgetConcept` maps **1:1** onto the LOCKED `BudgetLimitPolicy` with **no
schema change**:

| BudgetConcept | → `budget_limit` field | note |
|---|---|---|
| `limit_tokens: int \| None` | `max_tokens_per_period` | `0..1e12` |
| `limit_cost_cents: int \| None` | `max_cost_cents_per_period` | Delta emits **int**; an int is a valid JSON `number`; `0..1e11` |
| `period` | `period` | `hourly\|daily\|monthly` |
| `scope` | `scope` | `tenant\|team\|project\|agent` (Fork 1a → 1:1) |
| at-least-one-of {tokens, cost} | `anyOf` | BudgetConcept validator enforces the same rule |
| 4 IDs + policy_id/version/effective_from/signature | policy envelope | added by D-002 at emit time; the round-trip test stitches a full valid record |

**Flagged (non-blocking) seam:** the wire `max_cost_cents_per_period` is a JSON
`number` (float-capable), but Delta only ever emits and holds **integer cents**
(Fork 2). An integer validates against `number`, so the schema does not need to
move; Delta must never read a fractional-cents value back into a `BudgetConcept`
as a float — its cost field is integer cents. This compatibility is proven
empirically by `test_budget_variant_roundtrip.py`, which validates a
Delta-emitted `budget_limit` record against Sentinel's LOCKED
`policy.schema.json` using the same `Draft202012Validator` idiom the contract
mandates. **Reported: compatible; the locked policy schema is untouched.**

---

## Honesty boundary (mandatory)

D-001 ships the **model and its integrity invariants only**. It does **not**
enforce a budget, post to a ledger, or bill anyone — enforcement lives in **D-003**
(ledger engine) and **D-005** (budget engine). Monetary figures sourced from
Sentinel are *client-side cost estimates*, never authoritative bills. The types and
validators here are *risk reduction* through structural integrity, not a guarantee
of financial correctness of upstream inputs.

---

## Threat model (8 integrity vectors, with test paths)

| # | Vector | Defense | Test |
|---|---|---|---|
| 1 | **Float smuggling** — a monetary field accepts a float / `NaN` / `Infinity` and exactness is lost | `Money`/amount validator rejects non-`int` (and `bool`), `NaN`, `Inf` | `test_money.py` |
| 2 | **Unbalanced transaction** — a `Transaction` whose entries don't net to zero is constructed/accepted | frozen type + `@model_validator`: `Σdebit == Σcredit` or `ValidationError`; no constructor yields an unbalanced txn | `test_ledger_invariant.py` |
| 3 | **Negative / overflow amount** — `< 0` where forbidden, or `> wire max` | bounds: cost `0..1e11` cents, tokens `0..1e12`; negative rejected | `test_money.py` |
| 4 | **Reconciliation bypass** — allocation total ≠ Σ targets, or inconsistent entry set passes | reconciliation validators flag the violating set | `test_reconciliation.py` |
| 5 | **Burn-rate forgery** — a stored/mutable burn-rate desyncs from the ledger | burn-rate is derivation-only (no stored field); recompute matches | `test_burn_rate.py` |
| 6 | **JSON Schema permissiveness** — a missing `additionalProperties:false` or unbounded field opens a smuggling/DoS channel | every object closed + every field bounded; extra-key payload rejected | `test_json_schema_contracts.py` |
| 7 | **Cross-tenant attribution leakage** — a record without `tenant_id`, or mixed tenant within a transaction | `tenant_id` required on every tenant-scoped type; same-tenant invariant; RLS-shaped for D-003 | `test_attribution_mapping.py`, `test_ledger_invariant.py` |
| 8 | **Currency-mix / implied-enforcement** — netting two currencies as equal, or the model implying it enforces budgets | mixed-currency net rejected; ADR + docs state model + invariants ONLY | `test_ledger_invariant.py`, `test_budget_variant_roundtrip.py` |

---

## Consequences

**Positive:** lossless attribution against Sentinel events; exact money (no
floats); a non-bypassable double-entry invariant; tenant-first types that accept
F-003b RLS with zero reshape; proven compatibility with the LOCKED Budget variant
so D-002 needs no schema change; smallest surface that still serves the X-003
budget loop.

**Negative / accepted:** no org hierarchy yet (deferred to D-013+); sub-cent wire
estimates are quantized away at ingest (acceptable for an estimate); no
multi-currency / FX (deferred); no DDL here, so D-003 must turn these shapes into
the authoritative schema. None of these block the budget loop.

**Out of scope (explicit):** ledger posting engine (D-003), budget enforcement
engine (D-005), pricing tables, multi-currency conversion, organizational
hierarchy, any persistence/migration.

---

## Rollback

D-001 is purely additive: a new `Delta/` subtree (types, schemas, tests, docs) and
one scoped CI workflow. It adds no migration, touches no existing Sentinel code,
and leaves `contracts/policy.schema.json` byte-for-byte unchanged. Rollback =
revert the single squashed D-001 commit / drop the `Delta/src`, `Delta/contracts`,
`Delta/tests` additions; nothing else in the monorepo depends on it yet, so revert
is clean and total.
