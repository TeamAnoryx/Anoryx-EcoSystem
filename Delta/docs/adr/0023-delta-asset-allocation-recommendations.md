# ADR-0023 — Deterministic Risk-Tier Asset-Allocation + Micro-Investment Recommendations

- **Status:** Accepted
- **Date:** 2026-07-11
- **Task:** D-023 (Personal asset allocation + micro-investment recommendations) · Builder: FinOps
  backend
- **Depends on:** D-021 (`personal_finance` — the `personal_accounts` "investment" type label, and
  `personal_transactions` as the signed source of income/expense data)
- **Builds on:** D-021 ADR §3's own named deferral ("no investment/asset-allocation logic beyond
  the `investment` account type label — that is D-023's job") and D-011/D-012's disclosed-
  deterministic-heuristic-under-an-AI-sounding-name precedent — both reused, neither re-derived.
- **Supersedes:** nothing. Adds a new `delta.asset_allocation` package, one new migration (0016:
  `personal_allocation_recommendations`), and one new router mount to `allocation_admin/app.py`;
  does not alter any D-001…D-022 runtime behavior, contract, or persistence schema.

## 1. Context

The roadmap's literal title for D-023 is *"Personal asset allocation + micro-investment
recommendations,"* filed under Phase 4's B2C track with the same unbuildable literal dependency
D-021/D-022 already resolved: *"Depends on: D-003 + the B2C onboarding shell."* As established by
this same unattended run's research before starting (re-confirmed by reading D-021's and D-022's
own ADRs and code), no B2C onboarding shell, no bank-linking, and no real brokerage/market-data
integration exists anywhere in this codebase, and D-024/D-025 (the tasks that would provide real
money movement and real external account aggregation, respectively) are themselves still unbuilt.

D-021's own ADR (§3) already named this task's exact scope explicitly rather than leaving it
implicit: *"no investment/asset-allocation logic beyond the `investment` account type label — that
is D-023's named job."* D-021 shipped the `investment` value in `personal_accounts.type`'s CHECK
constraint and nothing else; this task is what builds on top of it.

This ADR builds D-023's title as a genuinely useful, honestly-scoped feature:

1. **Asset allocation** → a fixed, disclosed table of target allocation percentages (cash / bonds
   / equities) for three named risk tiers (conservative / moderate / aggressive), returned for a
   caller-chosen tier against a caller-designated `investment`-type personal account.
2. **Micro-investment recommendations** → a recommended one-time contribution amount: a fixed
   percentage of the tenant's own net income-minus-expense surplus (computed from real recorded
   `personal_transactions`) over a caller-specified window, floored to zero whenever that surplus
   is not positive.

Both are **plain, disclosed arithmetic over a fixed table** — not machine learning, not a live
market-data feed, not a personalized/predictive model, and not real investment execution. See §3
for what is explicitly NOT built.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — build on D-021's `personal_accounts`/`personal_transactions`, no new B2C identity fork** | A recommendation always targets an existing `personal_accounts` row (`tenant_id` + `account_id`), reusing ADR-0021 Fork 1's "a B2C consumer IS one `tenant_id`" resolution verbatim. | D-021's ADR (§3) named this task's dependency explicitly — reusing its account model rather than re-litigating the B2C-identity question D-021/D-022 already resolved differently for different reasons keeps this task's fork set small and consistent with the sibling task closest to it in scope (D-021, not D-022's enterprise reframing — because D-023 genuinely needs a per-consumer `investment` account, which only D-021's schema has). |
| **2 — a FIXED, three-tier target-allocation table, not a formula (age/glide-path) and not ML** | `RISK_TIER_TARGET_ALLOCATION_PCT` hardcodes `{conservative: 40/40/20, moderate: 20/30/50, aggressive: 10/15/75}` (cash/bonds/equities), chosen by the caller as an explicit enum, never derived from age or any other personal attribute this codebase does not collect. | Mirrors D-012/D-021's own precedent: no trained model, no forecasting/training-data precedent anywhere in this ecosystem, so a disclosed rules-based table is the honest choice over fabricating a personalization signal from data that isn't collected (no birthdate, no risk questionnaire exists). An age-based glide path was considered and rejected for the same reason: it would require inventing a data field with no real backing. Three tiers, not a continuous scale, keeps the table auditable and DB-CHECK-verifiable (each row's three percentages sum to exactly 100, enforced at the schema layer AND the DB layer). |
| **3 — micro-investment = a FIXED `MICRO_INVESTMENT_SURPLUS_RATE` (10%) of net window surplus, floored to integer minor units, floored to exactly 0 when surplus <= 0** | `recommended_micro_investment_minor_units = max(0, int(surplus_minor_units * 0.10))`. Never negative, never a fabricated positive figure when the tenant is running a deficit. | Mirrors D-021's own honesty rule (`_savings_points`/`_budget_points`: an absent or unfavorable signal scores as exactly that, never reweighted to look favorable). A tenant with a negative surplus gets an honest "invest nothing right now" signal (0), not a nonsensical negative investment or a silently-clamped positive one. `int()` truncation on a positive value floors toward zero, so the recommendation never exceeds what the fixed rate actually implies — the same "never over-recommend, round down" discipline D-008's `cost_per_request_cents` and D-021's `savings_rate` clamp already apply to monetary/ratio outputs. |
| **4 — surplus is computed TENANT-WIDE (all of the tenant's `personal_transactions`, not scoped to the target account)** | `store.get_net_surplus_minor_units` sums every transaction in the window regardless of `account_id`, then the recommendation is attached to the caller-chosen `investment` account. | An investment account's own transaction history is typically just inbound transfers (if recorded at all) — it does not reflect the tenant's actual income/spending capacity. "How much surplus do I have to invest" is inherently a whole-person question, not an account-scoped one; this mirrors how `personal_finance.get_financial_health` (D-021) already computes its own income/expense totals tenant-wide, not per-account. |
| **5 — query `personal_accounts`/`personal_transactions` directly, do NOT import `personal_finance.store`** | `asset_allocation.store` re-implements its own `get_account`/`get_net_surplus_minor_units` against `delta.persistence.models` directly. | Reuses ADR-0022 Fork 7's established precedent exactly: a new package reads a shared table directly via SQLAlchemy Core rather than importing another feature package's store-module functions, avoiding a cross-package interface coupling that could drift silently if `personal_finance.store` changes shape for its own reasons. |
| **6 — append-only history (SELECT, INSERT only — no UPDATE/DELETE grant)** | Mirrors D-022's `subscription_charges` / D-018's `invoice_payments`: every computed recommendation is a NEW row, migration 0016 grants `delta_app` only SELECT/INSERT on `personal_allocation_recommendations`. | A recommendation is a point-in-time computation against a moving input (the tenant's transaction history changes over time); the honest model is "here is what we recommended and when," not a single mutable "current recommendation" record that could be silently rewritten. Also lets `GET /recommendations` serve as an honest history a tenant/operator can review later. |
| **7 — NOT wired into D-009's hash-chained audit log** | Unlike D-022 (real financial mutations: subscription lifecycle, recorded charges), `asset_allocation` does not call `append_history`. | Mirrors D-021's own choice (`personal_finance.service` has no audit-log wiring at all): a recommendation is advisory output computed from already-audited underlying transaction data, not itself a financial transaction or a decision that moves money — it carries no independent audit-worthy fact beyond what `personal_transactions`/`personal_accounts` (D-021, unaudited-in-the-same-way already) already record. Reusing D-021's own precedent for this exact package shape rather than reusing D-022's (a different package, wiring genuine money-movement events) is the more directly comparable choice. |
| **8 — no client-supplied monetary or free-text field anywhere in this package's schemas** | `AllocationRecommendationRequest` carries only `tenant_id`/`account_id`/`risk_tier` (a closed enum)/`period_start`/`period_end`. Every dollar figure in the response is computed server-side. | Removes an entire class of injection/overflow/control-character vectors by construction rather than by validation — there is nothing for `reject_non_integer` or the control-character rejection helper every other Delta schemas module carries to guard, because no such field exists. Named explicitly in `schemas.py`'s own docstring as a deliberate absence, not an oversight. |
| **9 — mounted on the existing admin app, not a new process** | `GET /v1/admin/asset-allocation/risk-tiers`, `POST /v1/admin/asset-allocation/recommendations`, `GET /v1/admin/asset-allocation/recommendations` on the same D-007 admin app, same `require_admin` break-glass bearer auth. `risk-tiers` is the one route that performs NO DB access and NO tenant scoping (it returns the fixed table, not tenant data), still gated behind `require_admin` for consistency with every other route on this app rather than carving out a public exception. | Same operators, same auth, same trust boundary — mirrors every prior Delta admin feature's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No real investment execution, no brokerage/market-order integration, no actual money
  movement.** This task recommends a target allocation and a contribution amount; it does not, and
  cannot honestly claim to, execute a trade or move a single cent — that is D-024's job
  ("Real-time secure personal micro-transaction execution"), which does not exist in this
  codebase.
- **No live market data, no real asset pricing, no portfolio performance tracking, no
  rebalancing.** The percentages are a target allocation, not a valuation of what the tenant
  currently holds (this codebase has no concept of investment holdings/positions/prices at all).
- **No age-based, glide-path, or otherwise personalized allocation model.** Three fixed tiers,
  caller-selected — no data field (age, goals, time horizon beyond the tier label itself) exists
  in this codebase to personalize further, and inventing one would fabricate a signal this system
  does not actually have.
- **No tax-advantaged account type modeling (401(k)/IRA contribution limits, tax treatment).**
  `personal_accounts.type = "investment"` is a single undifferentiated bucket; this task does not
  add account sub-types or any tax-aware logic.
- **No persisted, reusable "risk profile."** A caller supplies `risk_tier` on every request; no
  new table stores a tenant's chosen tier as a standing preference. Real, plausible future work,
  named here rather than silently absent.
- **No ML/AI or trained statistical model of any kind.** A fixed lookup table plus one linear
  formula — mirrors D-011/D-012/D-021's own "AI-sounding roadmap name, disclosed deterministic
  heuristic" precedent, reused rather than re-litigated.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant account/surplus/recommendation leak | Every query runs on the caller's tenant-scoped (RLS) `AsyncSession`, opened via `get_tenant_session(tenant_id)` — the strict fail-closed NULLIF RLS predicate (migration 0016) confines every SELECT/INSERT to the caller's own tenant | `test_cross_tenant_recommendation_list_isolated`, `test_cross_tenant_recommendation_list_isolated_over_http`, `test_recommendation_against_another_tenants_account_raises` |
| A recommendation computed against another tenant's account (account_id guessed/enumerated) | `service.create_recommendation` checks `account.tenant_id != req.tenant_id` explicitly (the RLS-scoped `get_account` query itself already cannot see a cross-tenant row, so this is defense in depth against a NULL/None account read) before ever computing a surplus | `test_recommendation_against_another_tenants_account_raises`, `test_recommendation_against_missing_account_returns_404` |
| A recommendation computed against a non-`investment` account (checking/savings/etc.) | `service.create_recommendation` explicitly checks `account.type != "investment"` and raises before any surplus computation or write | `test_recommendation_against_non_investment_account_raises`, `test_recommendation_against_non_investment_account_returns_422` |
| A recommendation referencing a nonexistent `account_id` at the DB layer even if the app-layer check were bypassed | Composite `(account_id, tenant_id)` FK to `personal_accounts` (migration 0016) makes this structurally impossible | `test_recommendation_against_nonexistent_account_violates_fk` |
| Negative or fabricated-positive micro-investment recommendation | `_recommended_micro_investment_minor_units` floors to exactly 0 whenever `surplus_minor_units <= 0` (Fork 3); DB `CHECK (recommended_micro_investment_minor_units >= 0)` (migration 0016) as defense in depth | `test_negative_surplus_recommends_zero_never_negative`, `test_zero_surplus_recommends_zero` |
| Micro-investment recommendation rounds UP and over-recommends | `int()` truncation on a positive float floors toward zero (Python semantics, verified directly) | `test_micro_investment_floors_toward_zero_never_overrecommends` |
| Allocation percentages that don't sum to 100 (a corrupted/future edit to the fixed table) | DB `CHECK (cash_pct + bonds_pct + equities_pct = 100)` (migration 0016) + a unit test asserting every entry in `RISK_TIER_TARGET_ALLOCATION_PCT` sums to 100 | `test_every_risk_tier_allocation_sums_to_100` |
| Naive-datetime `period_start`/`period_end` silently misinterpreted as UTC | `require_aware_utc` (D-008's own validator, reused unchanged) rejects any period bound without an explicit timezone offset; `period_end <= period_start` also rejected at the schema layer, with `CHECK (period_end > period_start)` as DB-layer defense in depth | `test_naive_period_start_rejected`, `test_period_end_before_start_rejected`, `test_period_end_equal_start_rejected` |
| Recommendation history rewritten after the fact | No UPDATE/DELETE grant to `delta_app` on `personal_allocation_recommendations` (migration 0016, Fork 6) — enforced at the database ACL layer, not just application code | `test_recommendations_table_has_no_update_delete_grant` |
| Money handling: float/bool coercion into a monetary field | No client-supplied monetary field exists in this package at all (Fork 8) — every monetary figure in a response is computed server-side from already-validated `personal_transactions` rows, so there is no wire input to coerce | design-level (see Fork 8); `test_request_extra_field_rejected` / `test_unknown_risk_tier_rejected` cover the schema's actual (non-monetary) input surface |
| Unbounded `limit` on `GET /recommendations` used to force a large scan | `_clamp_limit` bounds every list query to `MAX_LIST_LIMIT = 500` server-side, same shape as `personal_finance`/`subscriptions` | code review — identical `_clamp_limit` helper to D-021/D-022, unchanged |
| Currency mismatch between an account and its surplus computation | `get_net_surplus_minor_units` is always called with `currency=account.currency` (the account's own declared currency, never a caller-supplied value) — mirrors D-021 ADR §2 Fork 9's currency-scoping fix | code review — no `currency` field exists on `AllocationRecommendationRequest` to mismatch |

## 5. Verification

- `black --check .` / `ruff check .` clean (verified locally against this diff).
- `alembic upgrade head` / `downgrade base` / `upgrade head` round trip (fresh Postgres, CI
  `migration-roundtrip` job) — the revision chain was confirmed to resolve to a single head
  (`0016`) locally via `alembic.script.ScriptDirectory`.
- `tests/asset_allocation/` suite: pure schema-validation unit tests (no DB/no I/O — 11 tests,
  verified passing locally), DB-backed store/service tests (real Postgres, real RLS, real FK/CHECK
  constraints) covering the account-type gate, the surplus formula against real recorded
  transactions, the floor-at-zero and floor-toward-zero rounding rules, and cross-tenant isolation,
  plus non-stubbed HTTP e2e tests (real ASGI app, real auth, real DB, accounts/transactions created
  through the actual D-021 HTTP endpoints rather than seeded directly) — DB-dependent tests
  self-skip in this sandboxed environment (no live Postgres available) and are the authority of
  the CI `ledger-db` job on a fresh Postgres, per this repo's banked "CI is authoritative" rule.
- Full Delta suite: not runnable end-to-end in this sandbox (no Docker/Postgres); CI is the
  authority per this run's own operating procedure.

## 6. Alternatives considered

- **A trained/ML-based personalization model (e.g. inferring risk tolerance from spending
  patterns).** Rejected: no training-data precedent exists anywhere in this ecosystem (mirrors
  D-011/D-012/D-021's own reasoning), and a caller-declared tier is more honest than a fabricated
  inference from data never collected for that purpose.
- **An age/glide-path-based allocation formula.** Rejected (Fork 2): would require inventing a
  data field (birthdate/target retirement date) this codebase does not collect anywhere.
- **Scoping the surplus computation to the target investment account's own transaction history.**
  Rejected (Fork 4): an investment account's own transactions are not a meaningful proxy for a
  tenant's actual income/spending capacity.
- **Importing `personal_finance.store`'s existing `get_income_expense_totals` directly.** Rejected
  (Fork 5): would couple this package to another feature's store-module interface rather than
  reading the shared table directly, diverging from the ADR-0022 Fork 7 precedent this task
  otherwise follows exactly.
- **Wiring every recommendation into D-009's hash-chained audit log, mirroring D-022.** Rejected
  (Fork 7): a recommendation is advisory output, not a financial mutation — D-021's own package
  (the more directly comparable precedent for this exact domain) does not audit-chain its writes
  either.
- **A B2C personal-subscription-style "enterprise reframing," mirroring D-022's Fork 1.** Rejected
  (Fork 1): D-021's ADR explicitly named this task as building on the `investment` account type —
  an enterprise reframe would ignore that already-made decision and would not need a personal
  `investment` account concept at all, making the task incoherent with its own dependency.
