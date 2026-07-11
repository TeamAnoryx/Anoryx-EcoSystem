# ADR-0021 — Personal Budget Tracking + Financial Health Score: A B2C Consumer IS One Tenant

- **Status:** Accepted
- **Date:** 2026-07-10
- **Task:** D-021 (AI personal budget tracking + financial health viz) · Builder:
  orchestration-hooks · Phase 4 (B2C personal finance, post-investment vision tier) —
  the first task in the D-021→D-025 B2C track, explicitly requested to complete
  despite its stated dependency on an unbuilt "B2C onboarding shell" (see §1).
- **Depends on:** D-001 (Delta's financial domain conventions — Money, Currency,
  tenant-scoped RLS). NOT D-003's `accounts`/`transactions`/`ledger_entries` (see
  Fork 2) — the roadmap's own "Depends on: D-003" is read as "reuses D-001-003's
  established conventions," not "writes into D-003's literal tables."
- **Builds on:** every D-013+ ADR's "stay structurally separate from the AI-cost
  ledger" discipline (most directly ADR-0018's own citation of D-014's identical
  precedent), and every D-013+ ADR's "name the unbuildable dependency honestly, build
  the real bounded slice" discipline (most directly ADR-0019's handling of D-019's
  seven-unbuildable-integrations gap).
- **Supersedes:** nothing. Adds a new `delta.personal_finance` package, three new
  tables (`personal_accounts`, `personal_transactions`, `personal_budgets`) via
  migration 0014, one new router mount to `allocation_admin/app.py`. No existing
  D-001–D-020 file's runtime behavior is modified.

## 1. Context

The roadmap's `Depends on` line for the whole B2C track (D-021→D-025) reads: *"D-003
+ the B2C onboarding shell."* Before starting this task, both halves of that
dependency were checked directly against the codebase:

- **D-003** (`delta.persistence.models.ledger_entries`) exists, but its schema bakes
  in `team_id`/`project_id`/`agent_id` as NOT NULL columns — these are AI-usage-cost
  dimensions (which team's/project's/agent's API calls cost how much), with no
  meaning for a person's grocery purchase. `accounts`/`transactions` (the other two
  D-003 tables) ARE generic enough to reuse verbatim, but reusing them without
  `ledger_entries` would mean building a parallel entry concept anyway.
- **"The B2C onboarding shell"** does not exist anywhere in this ecosystem. A direct
  search turned up no consumer identity/signup/auth model in Delta, and Rendly's
  R-023 ("Consumer onboarding") — the only other place a B2C onboarding concept has
  been built — explicitly disclaims building one in its own ADR-0023: *"no new B2C
  identity/signup/auth model, no persistence, no REST, no UI"* — it names that real
  system as still-unshipped, deferred work, the same way D-021 does here.

This task was explicitly requested despite that gap (a direct instruction to
complete D-021→D-025). Every D-013+ task in this codebase has faced an analogous
situation — a roadmap dependency or scope that cannot be honestly built as stated —
and resolved it the same way: name the real gap precisely, then build the largest
genuinely real, testable slice on top of what DOES exist. This ADR applies that
exact discipline to the B2C identity gap (Fork 1) and the D-003 ledger-shape gap
(Fork 2).

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — a B2C consumer IS one `tenant_id`, no new identity model** | Every request/view in `delta.personal_finance` is scoped by the existing `TenantId` type (an opaque UUID with no B2B semantics baked into its shape) — exactly like every B2B admin surface. No signup, no password, no session, no consumer-identity table. | `tenant_id` was already just an RLS scoping boundary, not a B2B-specific concept — reusing it costs nothing and is the only way to make genuine progress on this task without either building an entire separate identity/auth/signup system (a legitimately large, separate unit of work explicitly out of this task's scope) or silently pretending a shell exists. The real B2C onboarding shell — real signup, login, session management, a genuine end-user-facing product — remains named, deferred future work (§3), not a hidden prerequisite silently skipped. |
| **2 — a new, structurally separate personal-finance schema, not a reuse of D-003's ledger** | `personal_accounts`/`personal_transactions`/`personal_budgets` (migration 0014) are new tables. `personal_transactions` is single-entry (one signed `amount_minor_units` per row, category-tagged) — not D-003's double-entry `ledger_entries` shape. | Matches how real personal-finance apps (Mint, YNAB, Copilot Money) model spending — one categorized amount per transaction — not general-ledger double-entry bookkeeping, which is the right model for organizational accounting (D-003's actual job: tracking what an AI agent's API usage costs a team/project) but the wrong model for "I spent $42 at the grocery store." Jamming a personal purchase through `ledger_entries`'s `team_id`/`project_id`/`agent_id` NOT NULL columns would require inventing meaningless placeholder values for a consumer with no team/project/agent — a semantic corruption of the AI-cost ledger every D-013+ package has deliberately stayed out of (ADR-0018 §1 cites this exact precedent for invoicing; this is the ninth package to independently reach the same conclusion). |
| **3 — budget status is a same-period actual-vs-cap comparison, not a forecast/projection** | `FinancialHealthView.budgets` compares each category's ACTUAL spend in the queried window against its current cap (`over_cap: bool`) — no burn-rate projection, no period-end estimate. | D-011's forecasting module already owns projection math for the B2B AI-cost domain; duplicating that logic here for personal budgets would be premature scope for a first task in this track. A simple actual-vs-cap read is honest about what it is and sufficient for the roadmap's "budget tracking" framing — projected/forecasted personal budgets is reasonable, named future work (§3). |
| **4 — `personal_budgets` is INSERT-only; a budget change is a new row, not an UPDATE** | `create_budget` never updates an existing row. `get_latest_budgets` reads the most recent row per category (`ORDER BY created_at DESC`, one row per category via a `GROUP BY` subquery join). | Mirrors D-018/D-019's own "simplest possible write pattern" precedent: no UPDATE grant anywhere in this migration, so there is no concurrent-mutation race class to reason about at all — the safest way to avoid a mutation race is to have no mutation. |
| **5 — the health score is a disclosed, deterministic 0-100 heuristic, not machine learning or AI** | `health_score = savings_points (0-60) + budget_points (0-40)`. Savings points come from `(income - expense) / income` linearly mapped to `[0, 60]`, clamped to `[-1, 1]`; budget points come from the fraction of currently-defined budget categories within cap, linearly mapped to `[0, 40]`. Both formulas and their weights are documented in `service.py`'s module docstring. | Mirrors D-011's "predictive" forecasting (current-rate projection, not a trained model) and D-015's "AI-driven" bottleneck detection (a fixed heuristic) — both plain, disclosed arithmetic under an AI-sounding roadmap name. A consumer-facing "financial health score" that silently claimed to be AI/ML without being one would be a direct violation of this monorepo's honest-language mandate. |
| **6 — a missing signal scores as absent (0), never silently reweighted or assumed favorable** | If NO income was recorded in the window, `savings_points` is exactly `0` (not skipped, not treated as "N/A" that inflates `budget_points`' effective weight). If NO budgets are defined, `budget_points` is exactly `0` for the same reason. | Mirrors D-011's `insufficient_data` convention (never silently substituted with a favorable default) and D-008's `cost_per_request_cents: null` convention (never a divide-by-zero placeholder). A health score that quietly rewards having entered no data at all would be actively misleading — the honest answer to "no signal" is "this component contributes nothing," not "assume the best." |
| **7 — `delta.personal_finance` is gated by `require_admin` only, not retrofitted with D-017's RBAC** | `personal_finance/router.py`'s router-level dependency is `Depends(require_admin)` — the same break-glass bearer every surface except D-008's dashboards uses. | Mirrors every D-018/D-019/D-020 ADR's identical reasoning: D-017's RBAC retrofit was deliberately bounded to D-008's dashboards; this is an internal operator/testing surface until a real B2C onboarding shell (§3) exists to front it with genuine end-user auth — RBAC roles for a consumer product would need to be designed against that real auth model, not retrofitted onto a break-glass bearer meant for B2B operators. |
| **8 — mounted on the existing admin app, not a new process** | `POST/GET /v1/admin/personal-finance/{accounts,transactions,budgets}`, `GET /health-score` on the same D-007 admin app, alongside the other 12 mounted routers. | Same reasoning as every prior task: one app/port for the whole admin console. This is explicitly an OPERATOR/testing console for this task, not the eventual B2C consumer-facing product surface (§3) — that would need its own frontend, its own auth, and plausibly its own deployment, none of which are part of this task. |

## 3. Honest deferrals (named, not half-built)

- **No real B2C consumer identity/signup/auth model.** The single largest named gap
  (Fork 1). A real implementation needs: a consumer identity table set (distinct
  from any B2B admin-token model), a signup/login flow, session management, and
  probably its own REST surface — none of which exist in `contracts/openapi.yaml`
  or anywhere else in this ecosystem today. This is a legitimately large, separate
  unit of work; D-021's own ADR names it rather than silently building around it.
- **No consumer-facing UI.** `/personal-finance` is an OPERATOR console (behind the
  same break-glass bearer as every other admin page) — a real consumer product needs
  its own end-user-facing frontend, entirely outside this task's scope.
- **No projected/forecasted personal budgets** (Fork 3) — only same-period
  actual-vs-cap. A future task could extend D-011's forecasting math (or build an
  analogous personal-finance version) to project period-end spend per category.
- **No transaction editing or deletion.** `personal_transactions` is INSERT-only —
  correcting a miscategorized or duplicate transaction is not possible in this task
  (mirrors the same "simplest write pattern" discipline as Fork 4, extended to
  transactions too). A future task could add a bounded correction/reversal flow
  (mirrors D-003's own `reversal_of` column pattern) rather than a raw UPDATE.
- **No recurring-transaction detection or subscription management.** That is D-022's
  named job, building on this task's `personal_transactions` table.
- **No investment/asset-allocation logic beyond the `investment` account type
  label.** That is D-023's named job.
- **No real money movement.** Every transaction here is a caller-declared record
  (manual entry), never a real debit/credit against any bank/payment rail. D-024's
  job, and even there, scoped to Delta's own internal ledger only — see ADR-0024 when
  written.
- **No real bank data aggregation.** Every account/transaction here is
  operator/user-entered (`source = 'manual'`). D-025's named job — a generic
  ingestion framework (mirroring D-019's own precedent), not live Plaid/bank OAuth.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant leak — one consumer's accounts/transactions/budgets visible to another | Every store function runs inside the caller's own `get_tenant_session(tenant_id)`; `personal_accounts`/`personal_transactions`/`personal_budgets` all have `ENABLE`+`FORCE ROW LEVEL SECURITY` with the strict `NULLIF` predicate, `delta_app` is NOBYPASSRLS | `test_cross_tenant_isolation`, `test_create_transaction_against_other_tenants_account_raises`, `test_financial_health_cross_tenant_isolated`, `test_cross_tenant_accounts_isolated_over_http` |
| A transaction is recorded against an account that doesn't exist, or belongs to a different tenant | `create_transaction` (service layer) explicitly re-fetches the account and checks `account.tenant_id == req.tenant_id` before writing, raising `AccountNotFoundError` (404) otherwise — RLS alone would make a foreign-tenant account invisible (return `None`), but the explicit check makes the 404 path deliberate and tested rather than relying solely on RLS's side effect | `test_create_transaction_requires_existing_account`, `test_create_transaction_against_unknown_account_raises`, `test_create_transaction_against_other_tenants_account_raises`, `test_transaction_against_unknown_account_returns_404` |
| A session reused across two commits silently fails a subsequent RLS check (the exact bug class this session has hit repeatedly since D-018) | Every test helper/fixture that performs more than one commit opens a SEPARATE `get_tenant_session` block per commit — this bug was hit and fixed live while writing `test_service_db.py` (a `create_transaction` call reused the same session as a prior `create_account` commit and got a false `AccountNotFoundError`) | fixed in `tests/personal_finance/test_service_db.py`'s `_seed_account` helper and every multi-commit test |
| A `SUM()` aggregate returns a `Decimal` from asyncpg, silently breaking downstream `Decimal + float` arithmetic in the health-score formula | `store.get_income_expense_totals`/`get_category_spend` explicitly wrap every aggregate in `int(...)` at the query boundary (mirrors `dashboards.store`'s own identical `int(row[0])` convention) — this bug was hit and fixed live (`TypeError: unsupported operand type(s) for +: 'decimal.Decimal' and 'float'`) while writing `test_financial_health_composes_savings_and_budget_adherence` | that same test, now passing with an exact expected `health_score` assertion |
| A zero-amount transaction, or an amount so large it could silently overflow downstream aggregation | `TransactionCreateRequest` rejects `amount_minor_units == 0` and `abs(amount_minor_units) > MAX_AMOUNT_MINOR_UNITS` (1e11, same order of magnitude as every other Delta monetary overflow guard) | `test_transaction_create_request_rejects_zero_amount`, `test_transaction_create_request_rejects_overflow_amount` |
| A budget is created for a non-spending category (`income`/`transfer`) — a cap on money coming in makes no sense | `BudgetCategory` is a `Literal` type excluding `income`/`transfer` (a strict subset of `TransactionCategory`) | `test_budget_create_request_rejects_income_category` |
| Control-character / log-injection via `name`/`description`/`merchant` | Same `_reject_control_chars` discipline as every prior Delta package | `test_account_create_request_rejects_control_chars_in_name`, `test_transaction_create_request_rejects_control_chars_in_merchant` |
| Naive (non-UTC-aware) `occurred_at`/`start`/`end` silently misinterpreted | `require_aware_utc` rejects a naive datetime at the schema layer | `test_transaction_create_request_rejects_naive_occurred_at`, `test_financial_health_query_rejects_naive_start` |
| SQL injection via any personal-finance identifier or free-text field | Every query is a parameterized SQLAlchemy Core statement — no raw string-interpolated SQL anywhere in `delta.personal_finance.store` | code review |
| Auth bypass on any of the 6 new routes | Router-level `dependencies=[Depends(require_admin)]` covers all 6 with no per-route opt-out | `test_accounts_endpoint_401_without_bearer` |

## 5. Verification

- `black --check .` / `ruff check .` clean on the FULL repository.
- New `tests/personal_finance/` suite: 32 tests — 14 pure schema-validation tests
  (`test_schemas.py`, no DB/I/O), 6 DB-backed store tests (`test_store_db.py`,
  including the FK-enforced account requirement and cross-tenant isolation), 7
  DB-backed service tests (`test_service_db.py`, covering the full account/
  transaction/budget lifecycle and the health-score composition with an exact
  expected-score assertion), 5 non-stubbed HTTP e2e tests (`test_router_e2e.py` —
  real ASGI app, real auth, real DB).
- Full existing Delta suite green (929 passed, 15 skipped) — zero regressions.
- Migration 0014 applied cleanly against a live local Postgres (`alembic upgrade
  head`), `delta_app` role provisioned exactly as every prior migration's test
  harness does.
- Frontend: `tsc --noEmit` clean, `next lint` clean (0 warnings/errors on all new/
  modified files), `next build` succeeds with `/personal-finance` registered as a
  dynamic route. Live browser smoke test performed against a real running backend
  with real data entered through the UI itself: logged in via the break-glass token,
  loaded the (previously empty) personal-finance page, created an account through
  the UI form, recorded an income and a groceries expense transaction, set a
  groceries budget, loaded the 30-day window, and confirmed the financial-health
  section rendered with the exact expected score (95/100 — cross-checked against a
  direct follow-up API call: $2,500 income, $400 expense, savings rate 84%, one
  budget within cap → `savings_points = round((0.84+1)/2*60) = 55`,
  `budget_points = round(1/1*40) = 40`, total `95`).
- Independent security-auditor review: pending, findings will be recorded in
  `docs/audit/d-021-security-audit.md`.

## 6. Alternatives considered

- **Building the real B2C consumer identity/signup/auth model as a prerequisite
  before D-021's actual budget-tracking logic.** Rejected (Fork 1): that is a
  legitimately large, separate unit of work (its own schema, its own auth flow, its
  own REST surface) that would consume this entire task's scope without shipping
  any of the budget-tracking/financial-health logic the roadmap actually asks for.
  Reusing the existing `tenant_id` scoping boundary lets this task ship the real,
  testable domain logic now, with the identity gap named honestly rather than
  silently worked around or left completely unaddressed.
- **Reusing D-003's `accounts`/`transactions`/`ledger_entries` tables directly.**
  Rejected (Fork 2): `ledger_entries`'s NOT NULL `team_id`/`project_id`/`agent_id`
  columns have no honest value for a personal transaction — populating them with
  placeholder/sentinel values would be exactly the kind of "stub dressed up as a
  real integration" this session's engineering standards reject.
  `accounts`/`transactions` alone (without `ledger_entries`) would still require
  inventing a new entry-shape table, so there was no real savings from partial reuse.
- **A trained ML model (or an LLM call) for the financial-health score,** matching
  the roadmap's literal "AI personal budget tracking" title. Rejected (Fork 5): no
  labeled training data or real user financial outcomes exist anywhere in this
  environment to train or validate such a model against; a claimed-AI score with no
  verifiable basis would be a textbook case of this monorepo's banned
  compliance-washing language pattern, applied to a product claim instead of a
  security claim. A disclosed, deterministic formula is honest and immediately
  useful; mirrors D-011/D-015's identical resolution of the same "AI-named,
  actually-deterministic" pattern.
