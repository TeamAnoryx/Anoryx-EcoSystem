# ADR-0023 — Personal Asset Allocation + Micro-Investment Recommendations: A
Deterministic Advisory Engine Over Self-Reported Holdings

- **Status:** Accepted
- **Date:** 2026-07-11
- **Task:** D-023 (Personal asset allocation + micro-investment recommendations) ·
  Phase 4 (B2C personal finance, post-investment vision tier) — the third task in
  the D-021→D-025 B2C track.
- **Depends on:** D-021 (the `personal_accounts`/`personal_transactions` ledger and
  its `investment` account-type label — this task's own ADR-0021 §3 named
  "no investment/asset-allocation logic beyond the `investment` account type label"
  as explicitly D-023's job).
- **Builds on:** every D-021+ B2C-track ADR's "name the unbuildable dependency
  honestly, build the real bounded slice on top of what DOES exist" discipline
  (most directly ADR-0021 Fork 1's B2C-consumer-is-one-tenant_id reuse and
  ADR-0024's "no real money movement, name the gap" resolution for the sibling
  D-024 task).
- **Numbering note:** ADR-0024 (D-024, shipped ahead of this task on a parallel
  track) deliberately left this number free for D-023: *"ADR-0023 is deliberately
  left for D-023 (asset allocation + micro-investment)."*
- **Supersedes:** nothing. Adds a new `delta.investments` package, one new table
  (`investment_holdings` via migration 0017), one new identifier
  (`InvestmentHoldingId`), one new router mount to `allocation_admin/app.py`. No
  existing D-001–D-022 file's runtime behavior is modified.

## 1. Context

Read literally, "asset allocation + micro-investment recommendations" could imply
live market pricing, real brokerage connectivity, or a trained recommendation
model. Before starting, all three were checked directly against the codebase and
this environment:

- **No live market-data or pricing feed** of any kind exists anywhere in this
  codebase — no ticker/quote integration, no price-history table.
- **No brokerage/exchange/trade-execution integration** exists — D-024 (the
  sibling "execution" task) explicitly scoped itself to ledger-internal bookkeeping
  precisely because no payment rail or trading connection exists in this
  environment; the same gap applies here for security trades.
- **No labeled training data or real investment-outcome data** exists to train or
  validate a recommendation model against — the same gap ADR-0021 named for its
  "AI personal budget tracking" title (Fork 5 there).

What CAN be built honestly — and is genuinely the valuable part of an allocation
advisor — is a **deterministic rebalancing-and-contribution engine**: given what a
person has told the system they hold (in broad asset classes, not individual
securities/tickers) and a declared risk tolerance, compute (a) how far their
current mix has drifted from a disclosed target mix, and (b) how a proposed new
contribution should be split to move toward that target. This is exactly what
every "asset allocation" robo-advisor's rebalancing core does — target-weight
comparison, not stock-picking or market timing — made explicit and disclosed
rather than implied to be predictive intelligence.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — asset classes, not securities/tickers** | `investment_holdings` tracks a value per broad `asset_class` (stocks / bonds / cash_equivalents / real_estate / crypto / other) per account, not individual ticker positions. | Tracking real securities would require live pricing (Sec 1's named gap) to be honest about current value; a broad asset-class snapshot is exactly what a caller can honestly self-report without a market-data feed, and it is the correct granularity for a target-weight rebalancing model (which operates on asset-class mix, not stock-picking). |
| **2 — holdings are self-reported snapshots, INSERT-only** | `record_holding` never updates an existing row; a value change is a new row for that `(account_id, asset_class)` pair, and the store reads the latest row per pair (`get_latest_holdings`) — identical shape to D-021's own `personal_budgets`. | Mirrors this codebase's "simplest possible write pattern" precedent since D-018/D-019: no UPDATE grant anywhere in migration 0017, so there is no concurrent-mutation race class to reason about. A caller re-declaring a holding's value (e.g., after checking their brokerage statement) is a new observation, not a correction to history. |
| **3 — target allocation is a fixed, disclosed 3-profile table, not ML/AI, not live market data** | `_TARGET_ALLOCATIONS` in `service.py` hardcodes conservative/moderate/aggressive weight sets (each summing to exactly 1.0, asserted at module load and by a dedicated test). Rebalancing math is `target_pct - current_pct`, thresholded at 1 percentage point (`_DRIFT_THRESHOLD_PCT`) to avoid recommending action on noise. | Mirrors D-021's disclosed deterministic health-score formula and D-011's "predictive" forecasting (current-rate projection, not a trained model) — both plain arithmetic under an AI-sounding roadmap name. Claiming a personalized/learned allocation model with no real investment-outcome data to validate it against would be exactly the compliance-washing pattern this monorepo's honest-language mandate forbids, applied to a product claim. |
| **4 — a zero-value portfolio cannot be "rebalanced," only contributed to** | When `total_portfolio_value_minor_units == 0`, every line's `current_pct`/`drift_pct` is `None` (never a divide-by-zero placeholder — mirrors D-021's `FinancialHealthView.savings_rate` convention) and every `recommended_action` is `hold` with a zero rebalance amount. The `suggested_contribution_minor_units` split is still computed (Fork 5) — a brand-new investor has nothing to rebalance FROM but can still be told how to allocate new money. | A missing signal (no holdings recorded) must score as absent, never assumed favorable or fabricated into a specific dollar rebalance figure — the same rule ADR-0021 §2 Fork 6 applies to the health score's savings/budget components. |
| **5 — micro-investment contribution suggestion reuses D-021's own income/expense query, unmodified** | `get_allocation_recommendation` calls `personal_finance.store.get_income_expense_totals` (D-021's existing function, imported not duplicated) for the queried window, then suggests `_CONTRIBUTION_RATE` (20%, a module constant) of any POSITIVE surplus, floored at 0 if income is absent or expense meets/exceeds income. The total splits across asset classes by the SAME target weights via a largest-remainder allocation (`_split_by_weights`) so the per-class figures always sum exactly to the total. | Avoids duplicating D-021's income/expense aggregation logic (mirrors D-022's reuse of D-012's `detect_anomalies` unmodified — ADR-0022 Fork 1/2's precedent for cross-package reuse over reimplementation). A fixed contribution rate is a disclosed, non-caller-tunable safety-style default — the same posture D-024 applies to its execution caps (Fork 4 there): a suggestion a caller can inflate in the same request it applies to would not be an honest advisory figure. Largest-remainder (not naive per-line rounding) guarantees the parts sum exactly to the total — a naive `round()` per line can silently misstate a monetary total by a unit or two. |
| **6 — a holding may only be recorded against an `investment`-type account** | `record_holding` fetches the account via D-021's own `personal_finance.store.get_account`, requires it belongs to the caller's tenant (`AccountNotFoundError` otherwise — 404, mirrors D-021's own `create_transaction` behavior) AND that `account.type == "investment"` (`NotAnInvestmentAccountError` otherwise — 422). No DB-layer CHECK enforces this (Postgres cannot cross-table-CHECK); the service layer is the single enforcement point, mirrored by an explicit test for each branch. | A holding recorded against a `checking` account would be semantically meaningless for an allocation model (what does "40% of your checking account is in crypto" mean?) and would silently corrupt the whole-portfolio total. Explicit 404/422 branches (rather than a generic 500 or a silently-accepted bad row) make the contract precise and testable. |
| **7 — no D-009 audit-hash-chain entry for holdings** | Unlike D-022's charges or D-024's executions, recording a holding does NOT call `persistence.audit_log.append_history`. | A holding snapshot is a self-reported observation, not a financial EVENT (no money moved, no ledger row written) — mirrors D-021's own `personal_finance` package, which does not audit-chain its account/transaction/budget writes either. Consistency with the closest analog (D-021, the package this task extends) rather than the money-movement packages (D-022/D-024) it does not resemble. |
| **8 — single reporting currency, mirrors D-021's Fork 9 lesson learned from its own audit** | `get_latest_holdings(currency=...)` scopes both the portfolio total and the income/expense surplus query to ONE currency (`DEFAULT_CURRENCY` at the router layer); a holding recorded in a different currency is excluded from the total, never silently summed in as if it were the same unit. | D-021's own security audit caught exactly this class of bug (a currency-mismatched budget silently scored as within-cap) and fixed it by adding currency-scoping to `get_latest_budgets`. This task applies that same lesson from the start rather than repeating the mistake and needing a second audit-driven fix. |
| **9 — mounted on the existing admin app, `require_admin` only** | `POST/GET /v1/admin/investments/holdings`, `GET /v1/admin/investments/allocation-recommendation` on the same D-007 admin app, alongside the other 14 mounted routers. | Same reasoning as every prior D-013+ task: one app/port for the whole admin console; an internal operator/testing surface until a real B2C onboarding shell (still unbuilt anywhere in this ecosystem) exists to front it with genuine end-user auth. |

## 3. Honest deferrals (named, not half-built)

- **No live market data or pricing.** Every holding value is exactly what the
  caller declares; there is no quote/ticker integration to mark a position to
  market. A future task could add a read-only market-data adapter, but the
  advisory math here would not change (it operates on declared values regardless
  of source).
- **No individual security/ticker tracking**, only broad asset classes (Fork 1). A
  future extension could add a `symbol` field for informational display without
  changing the allocation math, which is class-level by design.
- **No trade execution, no brokerage/exchange connectivity.** Every recommendation
  is advisory text (a suggested dollar amount to move toward), never an executed
  transaction. Unlike D-024 (which DOES write real `personal_transactions` rows for
  its ledger-internal "execution"), this task writes NOTHING to the ledger — a
  recommendation is read-only.
- **No per-tenant custom risk profiles or target weights.** Three fixed profiles
  only (Fork 3). A future task could add an operator-defined custom target-weight
  editor.
- **No tax-aware or account-type-aware rebalancing** (e.g., preferring to
  rebalance within a tax-advantaged account first). The engine treats all of a
  tenant's `investment`-type accounts as one pooled portfolio.
- **No real bank/brokerage data aggregation.** Same deferral D-021 named for
  D-025's job — every holding here is caller/operator-entered.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant leak — one tenant's holdings/recommendation visible to another | Every store function runs inside the caller's own `get_tenant_session(tenant_id)`; `investment_holdings` has `ENABLE`+`FORCE ROW LEVEL SECURITY` with the strict `NULLIF` predicate, `delta_app` is NOBYPASSRLS | `test_cross_tenant_isolation`, `test_record_holding_against_other_tenants_account_raises`, `test_cross_tenant_holdings_isolated_over_http` |
| A holding is recorded against an account that doesn't exist, belongs to another tenant, or isn't an `investment` account | `record_holding` explicitly re-fetches the account and checks tenant ownership (`AccountNotFoundError`, 404) and `type == "investment"` (`NotAnInvestmentAccountError`, 422) before writing — RLS/FK alone would not catch the type mismatch | `test_record_holding_against_unknown_account_raises`, `test_record_holding_against_other_tenants_account_raises`, `test_record_holding_against_non_investment_account_raises`, `test_holding_against_unknown_account_returns_404`, `test_holding_against_non_investment_account_returns_422` |
| Mixed-currency holdings silently summed into one portfolio total | `get_latest_holdings`/the recommendation path are currency-scoped to the report currency; a non-matching-currency holding is excluded, never coerced (Fork 8) | `test_get_latest_holdings_currency_scoped`, `test_allocation_recommendation_currency_scoped` |
| Divide-by-zero / fabricated percentage on an empty portfolio | `current_pct`/`drift_pct` are `None`, not `0.0` or a crash, when `total_portfolio_value_minor_units == 0` (Fork 4) | `test_allocation_recommendation_empty_portfolio_no_income_suggests_nothing` |
| Contribution-split rounding silently misstates the total (parts don't sum to the whole) | Largest-remainder allocation (`_split_by_weights`) guarantees an exact sum | `test_allocation_recommendation_suggests_contribution_from_surplus` (asserts `sum(line splits) == total`) |
| A target-allocation table with weights that don't sum to 1.0 (a silently wrong "100%") | Module-load `assert` in `service.py` + a dedicated regression test | `test_target_allocations_sum_to_one` |
| A zero-amount or negative holding value | `value_minor_units` is `ge=0` at the schema layer (422); `reject_non_integer` rejects float/bool wire values | `test_holding_record_request_rejects_negative_value`, `test_holding_record_request_rejects_float_value` |
| An amount so large it could silently overflow downstream aggregation | `value_minor_units le=MAX_AMOUNT_MINOR_UNITS` (1e11, same order of magnitude as every other Delta monetary overflow guard) | `test_holding_record_request_rejects_overflow_value` |
| Naive (non-UTC-aware) `start`/`end` on the recommendation query silently misinterpreted | `require_aware_utc` rejects a naive datetime at the schema layer (422) | `test_allocation_query_rejects_naive_start` |
| Auth bypass on either of the 2 new routes | Router-level `dependencies=[Depends(require_admin)]` covers both with no per-route opt-out | `test_holdings_endpoint_401_without_bearer` |
| SQL injection via any investments identifier or field | Every query is a parameterized SQLAlchemy Core statement — no raw string-interpolated SQL anywhere in `delta.investments.store` | code review |

## 5. Verification

- `black --check .` / `ruff check .` clean on the FULL repository.
- New `tests/investments/` suite: pure schema-validation tests (`test_schemas.py`,
  no DB/I/O, incl. the target-allocation-sums-to-1.0 invariant), DB-backed store
  tests (`test_store_db.py`, incl. multi-account summation, currency scoping,
  cross-tenant isolation), DB-backed service tests (`test_service_db.py`, covering
  the empty-portfolio honesty guard, the surplus-derived contribution split with
  exact expected figures, overweight/underweight/on-target rebalancing, and
  currency scoping), and non-stubbed HTTP e2e tests (`test_router_e2e.py` — real
  ASGI app, real auth, real DB).
- Full existing Delta suite green — zero regressions.
- Migration 0017 applied cleanly against a live local Postgres (`alembic upgrade
  head` / `downgrade base` / `upgrade head` round trip).
- Independent security-auditor review: verdict **CLEAN** of High/Critical
  findings. One Medium finding (the portfolio total was computed via a
  list-endpoint query capped at 500 rows, silently truncating a large
  portfolio's aggregate) and one Low (a currency-omitted grouping key hid a
  same-account, same-class holding recorded in a second currency) — both fixed
  before merge with three new regression tests. Two further Low findings
  (hardcoded USD reporting currency; an unreachable-in-practice `created_at`
  timestamp-tie edge case, both identical in shape to pre-existing D-021
  precedent) are documented as residual scope, not fixed. Full detail:
  `docs/audit/d-023-security-audit.md`.

## 6. Alternatives considered

- **Individual security/ticker-level holdings with live pricing.** Rejected
  (Fork 1, Sec 1): no market-data feed exists anywhere in this codebase or
  environment; fabricating one, or accepting caller-declared "current market
  value" per ticker with no way to verify it, would not be meaningfully more
  honest than the broad-asset-class model actually shipped, while adding
  substantial scope (symbol validation, a pricing adapter interface) this task
  does not need for a target-weight rebalancing engine.
- **A trained ML recommendation model.** Rejected (Fork 3, Sec 1): no labeled
  training data or real investment-outcome data exists anywhere in this
  environment to train or validate such a model against — the same reasoning
  ADR-0021 applied to its own "AI personal budget tracking" title.
- **Executing the recommended rebalance automatically** (writing ledger
  transactions for the suggested buy/sell amounts). Rejected: this task is
  explicitly a RECOMMENDATION engine (read-only); D-024 already drew the line on
  what "execution" honestly means in this codebase (ledger-internal bookkeeping,
  not real trades) — auto-executing a security trade recommendation would imply a
  brokerage connection that does not exist.
- **A caller-tunable contribution rate.** Rejected (Fork 5): a suggested
  contribution a caller can inflate in the same request it applies to is not an
  honest advisory figure, mirroring D-024's identical reasoning for its execution
  caps.
