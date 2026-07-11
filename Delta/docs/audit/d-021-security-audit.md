# D-021 Security Audit — Personal Budget Tracking + Financial Health Score (B2C Track)

- **Date:** 2026-07-10
- **Scope:** `Delta/src/delta/personal_finance/` (the entire new package —
  `schemas.py`, `store.py`, `service.py`, `router.py`),
  `Delta/src/delta/persistence/migrations/versions/0014_personal_finance_core.py`
  (new `personal_accounts`/`personal_transactions`/`personal_budgets` tables, RLS,
  SELECT+INSERT-only grants, CHECK constraints, composite tenant-scoped FK), the
  additive changes to `identifiers.py`/`persistence/models.py`, the one new router
  mount in `allocation_admin/app.py`, `Delta/tests/personal_finance/` (read for
  coverage/gaps), the new frontend surface
  (`Delta/frontend/src/app/(admin)/personal-finance/`,
  `Delta/frontend/src/components/personal-finance/`, and the additive changes to
  `types.ts`/`admin-client.ts`/`bff.ts` including the `"personal-finance"`
  `ALLOWED_ROOTS` addition). ADR-0021 existed at review time and was used to
  distinguish deliberate design decisions (a B2C consumer IS one `tenant_id` behind
  the operator break-glass bearer; a schema structurally separate from D-003's
  ledger; INSERT-only writes; a disclosed deterministic health score) from candidate
  bugs.
- **Reviewer:** independent security-auditor pass, arms-length from the implementer,
  performing its own read of every source file rather than trusting the task
  description. A Semgrep registry pull (`p/python`/`p/security-audit`/`p/secrets`)
  was blocked by this environment's egress policy (the same known limitation recorded
  in every prior audit this session); the reviewer did not route around the policy
  and substituted a full manual review of the trust boundaries.
- **Verdict:** **CLEAN of High/Critical findings.** Two **Low** findings
  (correctness/robustness with security-adjacent consequences, no data leak, no auth
  gap) — **both fixed below, before this diff shipped.**

## Findings

### Low — budget adherence compared a non-report-currency cap against report-currency spend, silently scoring an overspent category as within-cap (FIXED)

- **Location:** `Delta/src/delta/personal_finance/store.py` (`get_latest_budgets`,
  pre-fix) / `service.py` (`get_financial_health`).
- **Issue:** `get_latest_budgets()` returned every category's latest budget
  regardless of currency, while the spend figures it was compared against
  (`get_category_spend`/`get_income_expense_totals`) were hard-scoped to the report
  currency (USD, per `router.py`'s `DEFAULT_CURRENCY`). The schemas allow any
  ISO-4217 currency on both budgets and transactions, so for a tenant whose data is
  entirely non-USD, the health endpoint compared a EUR cap against a USD-scoped
  spend of 0 — `over_cap` was silently `False` even when that category was massively
  overspent, and the budget-adherence component contributed a perfect score computed
  from an effectively empty dataset.
- **Exploit scenario:** `POST /budgets {category: 'dining', cap: 10000, currency:
  'EUR'}`; `POST /transactions {category: 'dining', amount: -500000, currency:
  'EUR'}`; `GET /health-score` → `budgets[dining].over_cap = false`, `spent = 0`,
  budget adherence 40/40 — a wrong financial-health signal (the same
  figure-honesty bug class D-020's audit caught in its pipeline count/value
  pairing). No cross-tenant impact, no data leak.
- **Fix applied:** `get_latest_budgets` now takes a `currency` parameter. The
  health-score path passes the report currency — a budget capped in a different
  currency is EXCLUDED from the adherence calculation entirely (never silently
  scored as within-cap), while the plain `GET /budgets` list endpoint remains
  unscoped since each returned row carries its own currency label. New regression
  tests: `test_get_latest_budgets_currency_scoped` (store) and
  `test_financial_health_excludes_non_report_currency_budget` (service — asserts the
  overspent EUR budget contributes NOTHING to the score, `health_score == 0`).
- **Residual scope note:** single-currency reporting (D-001's no-FX rule) remains
  the package-wide convention — a multi-currency consumer sees each budget honestly
  labeled in the list view, and the health score covers the report currency only.
  Multi-currency health reporting (per-currency scores, or an explicit currency
  query param on `/health-score`) is reasonable named future work, not built here.

### Low — `GET /transactions`' `start`/`end` window params accepted naive datetimes and inverted windows (FIXED)

- **Location:** `Delta/src/delta/personal_finance/router.py` (`get_transactions`,
  pre-fix).
- **Issue:** unlike `FinancialHealthQuery` (which validates via `require_aware_utc`
  and `end > start`), the transactions-list route's optional `start`/`end` query
  params flowed unvalidated into a comparison against the `timestamptz`
  `occurred_at` column — a naive datetime is either silently misinterpreted (a wrong
  window presented as correct) or raises in asyncpg, surfacing as a generic 500 via
  the app's failsafe handler. Robustness/correctness only; no isolation or auth
  impact.
- **Fix applied:** the route now mirrors the health route's validation —
  `require_aware_utc` on each supplied bound plus `end > start` when both are
  supplied, returning 422 at the boundary. New regression tests:
  `test_transactions_list_rejects_naive_start_over_http`,
  `test_transactions_list_rejects_end_before_start_over_http`.

## What was actively verified and found sound

- **Authentication.** `require_admin` is a router-level dependency on the
  `APIRouter` and all 6 routes inherit it (constant-time `hmac.compare_digest`,
  Bearer scheme required, fail-loud token load) — no auth gap, no per-route opt-out.
- **Cross-tenant isolation.** RLS is `ENABLE` + `FORCE` with the strict `NULLIF`
  transaction-local GUC predicate on all three new tables; `delta_app` is
  `NOBYPASSRLS`; every query runs in the caller's own `get_tenant_session(tenant_id)`
  with `WITH CHECK` enforced on INSERT; the composite `(account_id, tenant_id)` FK
  plus the redundant service-level `AccountNotFoundError` check close the
  cross-tenant transaction-write path — no cross-tenant read or write found.
- **SQL injection.** All SQL is SQLAlchemy Core with bound parameters — no
  string-interpolated SQL anywhere in the package; the RLS GUC itself is set via a
  bound parameter.
- **Input validation.** Nonzero/bounded/strictly-integer amounts (bool and float
  rejected), control-character rejection on all free text, aware-UTC datetimes on
  create paths, `end > start` on the health window, server-side clamped list limits.
- **The Decimal→`int()` fix** (a real bug caught during implementation): confirmed
  complete — both `SUM()` aggregate paths are wrapped, and no other unguarded
  aggregate exists in the package.
- **The RLS session-reuse fix** (the recurring bug class this session has hit since
  D-018): confirmed no PRODUCTION code path reuses a session across two commits; the
  test-suite fix pattern (separate `get_tenant_session` block per commit) is applied
  consistently.
- **BFF `ALLOWED_ROOTS` += `"personal-finance"`.** Identical handling to the other
  12 allow-listed roots — first-segment gate, unchanged traversal guard, per-segment
  encoding; maps to the real `/v1/admin/personal-finance` router prefix. No new
  SSRF/path-traversal surface.

## Verification after fixes

- `Delta/tests/personal_finance/` — 36 tests (up from 32: four new regression tests
  across the two findings), all passing against live local Postgres.
- `black --check .` / `ruff check .` clean on the full repository.
- ADR-0021 §2 Fork 9 records both findings and their fixes.
