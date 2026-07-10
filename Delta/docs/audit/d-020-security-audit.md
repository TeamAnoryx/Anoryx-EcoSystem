# D-020 Security Audit — Executive Financial Dashboard: A Composed Read-Only Rollup

- **Date:** 2026-07-10
- **Scope:** `Delta/src/delta/executive/` (the entire new package — `schemas.py`,
  `store.py`, `service.py`, `router.py`), the one new router mount in
  `Delta/src/delta/allocation_admin/app.py`, `Delta/tests/executive/` (read for
  coverage/gaps), the new frontend surface (`Delta/frontend/src/app/(admin)/
  executive/page.tsx`) and the additive changes to `types.ts`/`admin-client.ts`/
  `bff.ts` (in particular the `"executive"` addition to `ALLOWED_ROOTS`). ADR-0020
  existed at review time and was used as context for which design decisions were
  deliberate (read-only, no caching, single-currency, no RBAC retrofit, `now` as an
  explicit parameter) versus candidate bugs.
- **Reviewer:** independent security-auditor pass, arms-length from the implementer.
  Focus areas per the task brief: cross-tenant data leakage across all three composed
  reads (spend/forecasts/pipeline), auth bypass, SQL injection in the new
  `store.get_pipeline_summary` query, input validation gaps (naive datetimes,
  `end <= start`, malformed tenant_id), correctness bugs with security-adjacent
  consequences (a stale/incorrect figure reported as authoritative), and the BFF
  `ALLOWED_ROOTS` addition for path-traversal/unintended-proxy-target risk. The
  reviewer was specifically asked to verify the `now`-as-parameter fix (ADR-0020 §2
  Fork 3) was complete, since that fix addressed a real bug caught during
  implementation. A Semgrep registry pull (`p/python`/`p/security-audit`/`p/secrets`)
  was blocked by this environment's egress policy (the same known limitation recorded
  in every prior audit this session); the reviewer substituted an offline Semgrep pass
  plus manual data-flow review, and did not retry the blocked registry pull.
- **Verdict:** No High/Critical findings. One **Medium** and one **Low** finding, both
  concerning honest presentation of figures rather than data leakage or auth — **both
  fixed below, before this diff shipped.**

## Findings

### Medium — `budget_count`/forecast-derived figures silently capped at 100, presented as tenant-wide totals without any truncation signal (FIXED)

- **Location:** `Delta/src/delta/executive/service.py:47` (pre-fix).
- **Issue:** `get_executive_summary` called `forecast_all_budgets(session, now=now,
  limit=500)`. `forecast_all_budgets` passes that limit straight into
  `budget_engine.definitions.list_budgets`, which silently clamps any requested limit
  to `MAX_LIST_LIMIT = 100` (`budget_engine/definitions.py:22,155`). Every D-011-derived
  figure in the executive view (`budget_count`, `total_current_period_spend_cents`,
  `total_projected_period_end_spend_cents`, `budgets_at_critical`,
  `budgets_at_warning`, `budgets_insufficient_data`) therefore reflected only the
  oldest 100 budgets (`ORDER BY created_at`) for a tenant with more than 100 budget
  definitions, while being presented as the authoritative tenant-wide executive total
  — with `limit=500` in the call site actively misleading a reader of the code into
  thinking coverage extended past 100.
- **Exploit scenario:** A tenant with 150 budget definitions has budgets 101-150
  blown well past their caps (genuinely `critical`). An executive loads
  `GET /v1/admin/executive/summary` and sees e.g. `budgets_at_critical=0` and a low
  `total_current_period_spend_cents`, because only budgets 1-100 (the oldest,
  presumably longest-settled ones) were ever queried. The dashboard reports a clean
  financial picture that is false — exactly the "stale/incorrect figure reported as
  authoritative" class the audit was asked to hunt for, and a direct violation of this
  monorepo's "honest language" mandate (no silently-truncated figure presented as
  complete).
- **Fix applied:**
  1. Replaced the misleading `limit=500` with a named `_MAX_FORECAST_BUDGETS = 25`
     constant, matching `forecasting.router`'s own cost-conscious list cap (the same
     per-budget multi-query cost concern that cap already exists for applies
     identically here) rather than inventing a request the callee could never honor.
  2. Added `budgets_truncated: bool` to `ExecutiveSummaryView` — `True` iff
     `budget_count` hit `_MAX_FORECAST_BUDGETS`, an honest signal that a tenant may
     have more budgets than were aggregated. Surfaced on the frontend as a hint on the
     "Budgets" stat tile ("capped — figures below may under-count").
  3. New regression test `test_executive_summary_signals_budgets_truncated_at_the_forecast_cap`
     seeds exactly 25 budgets and asserts `budgets_truncated is True`; existing tests
     assert `budgets_truncated is False` for small budget counts.
- **Residual scope note:** the underlying bound (25, or the generic 100) is an
  existing, deliberate Delta-wide convention (mirrors D-007/D-008's own list-response
  caps) that this task does not change — a tenant with more budgets than the cap still
  gets a partial rollup, but now knows it. Building a genuinely uncapped tenant-wide
  aggregate (a dedicated SQL `SUM`/`COUNT` query instead of materializing per-budget
  forecast views) is a reasonable follow-up, not built here, to avoid scope creep
  into forecasting's own list-cap convention.

### Low — `open_deal_count` and `open_pipeline_value_minor_units` described different deal sets under one currency label (FIXED)

- **Location:** `Delta/src/delta/executive/store.py:43` (pre-fix).
- **Issue:** `open_deal_count` counted every non-terminal deal regardless of
  currency, while `open_pipeline_value_minor_units` summed only deals in
  `DEFAULT_CURRENCY` ("USD") — the response paired a count spanning every currency
  with a value covering only USD deals, both presented under one
  `pipeline_currency: "USD"` label. The docstring documented the null-value-still-
  counted behavior but not this currency inconsistency.
- **Exploit scenario:** A tenant with 10 open deals (3 USD, 7 EUR) sees
  `open_deal_count=10`, `open_pipeline_value_minor_units` = sum of the 3 USD deals
  only, `pipeline_currency="USD"` — an executive reads "10 open deals worth $X" where
  $X silently excludes 7 of them.
- **Fix applied:** `open_deal_count`'s query now filters
  `or_(deals.c.currency.is_(None), deals.c.currency == currency)` — the same currency
  scope as the value sum, so both figures describe the same deal set. A deal with a
  NULL currency (an unqualified early-stage lead, D-013's own pairing discipline)
  still counts but contributes no value, matching the pre-existing, correctly-honest
  null-handling behavior. New regression tests
  `test_pipeline_summary_scoped_to_currency` (now also asserts `open_deal_count == 1`
  when a same-tenant EUR deal exists) and
  `test_pipeline_summary_null_currency_deal_still_counted_with_other_currency_present`
  (confirms a null-currency lead still counts alongside an excluded EUR deal).

## What was actively verified and found sound

- **Cross-tenant leak (all three composed reads).** `get_summary` (D-008),
  `forecast_all_budgets` (D-011), and `get_pipeline_summary` (D-020, new) all run
  inside the caller's single `get_tenant_session(tenant_id)` (`router.py:37`), which
  sets the transaction-local `app.current_tenant_id` GUC. `clients`/`deals`
  (migration `0007_unified_crm.py`) and `budget_definitions` (`0003_budget_engine.py`)
  both have `ENABLE` + `FORCE ROW LEVEL SECURITY` with the strict
  `NULLIF(current_setting(...),'')` predicate, and `delta_app` is `NOBYPASSRLS`. The
  new `store.get_pipeline_summary` has no explicit tenant filter in its own SQL but is
  fully RLS-confined by the session it runs in — confirmed by
  `test_pipeline_summary_cross_tenant_isolated`,
  `test_executive_summary_cross_tenant_isolated`,
  `test_cross_tenant_summary_is_isolated_over_http`.
- **Auth bypass.** The route is gated at `APIRouter(prefix=...,
  dependencies=[Depends(require_admin)])` (`router.py:20`), applying to the one
  `/summary` route. `require_admin` is fail-closed with a constant-time
  `hmac.compare_digest`. No unauthenticated path — confirmed by
  `test_get_summary_missing_bearer_is_401`.
- **SQL injection.** `store.py`'s query is genuine SQLAlchemy Core (`select`,
  `func.count`, `func.sum`, `.where(...)`, bound `currency` parameter) — no raw
  string-interpolated SQL anywhere in the package.
- **Input validation.** `ExecutiveSummaryQuery` enforces timezone-aware UTC via
  `require_aware_utc` and `end > start`; `tenant_id` is the strict canonical-UUID
  `TenantId` constraint. Malformed/naive/oversized inputs 422 before any DB work —
  confirmed by `test_executive_summary_query_rejects_end_before_start`,
  `test_executive_summary_query_rejects_equal_start_end`,
  `test_executive_summary_query_rejects_naive_start`,
  `test_get_summary_rejects_end_before_start_over_http`.
- **The `now` fix (ADR-0020 §2 Fork 3).** Verified complete: `router._now()`
  resolves the wall clock once and passes it in; `service.get_executive_summary` uses
  that single `now` for both `forecast_all_budgets` and `generated_at`; `get_summary`
  operates purely on the caller-supplied `[start, end]` window and reads no clock;
  `store.py` reads no clock. No residual silent `datetime.now()` call anywhere in the
  package. The fix does not introduce a new correctness issue.
- **BFF `ALLOWED_ROOTS` += `"executive"`.** The value only gates the first path
  segment against the allow-list; the existing traversal guard (rejects `..`/`.`/
  `/`/`\`) and `encodeURIComponent` per-segment handling are unchanged, and it maps to
  the real `/v1/admin/executive` router prefix. No new SSRF/path-traversal surface —
  identical handling to the other 11 allow-listed roots.

## Verification after fixes

- `Delta/tests/executive/` — 20 tests (up from 18: two new regression tests for the
  Medium and Low findings), all passing against live local Postgres.
- Full existing Delta suite green (897 passed, 15 skipped) — zero regressions.
- `black --check .` / `ruff check .` clean on the full repository.
- Frontend `tsc --noEmit` and `next lint` clean on all changed files.
