# ADR-0020 — Executive Financial Dashboard: A Composed Read-Only Rollup, Not New Math

- **Status:** Accepted
- **Date:** 2026-07-10
- **Task:** D-020 (Executive financial dashboard) · Builder: orchestration-hooks ·
  Phase 3 (post-investment vision) — the eighth task built past Delta's committed
  MVP (D-001→D-012), continuing directly after D-019 per the standing "complete all
  post-investment tasks" instruction. This is the final task in the "Delta Enterprise
  OS" D-013→D-020 arc.
- **Depends on:** D-008 (`delta.dashboards` — spend summary), D-011
  (`delta.forecasting` — per-budget forecasts/recommendations), D-013 (`delta.crm` —
  client/deal pipeline). The roadmap's own `Depends on` line names exactly these
  three; this task does not attempt a rollup across every one of the 13 modules
  shipped since D-007.
- **Builds on:** every prior D-013→D-019 ADR's honesty-boundary discipline — scope
  is anchored to the roadmap's explicit dependency line, not to a literal reading of
  "across the OS."
- **Supersedes:** nothing. Adds a new `delta.executive` package (four files, no
  migration), one new router mount to `allocation_admin/app.py`. No existing
  D-007–D-019 file's runtime behavior is modified except one signature change (§2
  Fork 3).

## 1. Context

The roadmap's literal text for D-020 is: *"Top-level executive financial view across
the OS."* Read the most expansively, "across the OS" could mean pulling data from
every one of the 13 Delta modules shipped in this session (allocations, dashboards,
forecasting, chargeback, CRM, ERP, PM, capacity, RBAC, invoicing, integrations) plus
Sentinel/Orchestrator. The roadmap itself narrows this: its own `Depends on: D-008,
D-011, D-013` line names exactly three modules — spend, budget forecasts, and CRM
pipeline. Every prior D-013→D-019 ADR in this arc applied the same discipline
(anchor to the roadmap's own explicit dependency line, not an unbounded reading of
its prose title), and this task continues that pattern rather than inventing scope
an unattended pass cannot responsibly verify against modules it wasn't asked to
touch. Unlike every other task since D-018, this is a pure read-only rollup: zero
new tables, zero new migration, zero write path — the simplest and lowest-risk task
in the entire D-013→D-020 arc (Risk: LOW per the roadmap itself).

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — reuse D-008's and D-011's own SERVICE functions, not their underlying tables** | `get_executive_summary` calls `dashboards.service.get_summary` and `forecasting.service.forecast_all_budgets` directly and sums/aggregates their typed return values. It does NOT re-query `ledger_entries`/`budget_definitions` to re-derive burn rate or forecast projections. | Burn-rate and forecast-projection math is nontrivial, already implemented, and already tested in D-008/D-011. Re-deriving it here would risk drift between two independent implementations of the same formula — the correct DRY boundary for a rollup whose entire purpose IS composing other modules' outputs. This is a deliberate departure from D-018/D-019's own "query the shared table directly" convention, which applies to a simple existence/amount check, not to reusing nontrivial aggregate computation. |
| **2 — the D-013 CRM pipeline rollup is a new local read, not a reused service** | `delta.executive.store.get_pipeline_summary` queries `clients`/`deals` from `persistence.models` directly (count of clients, count/sum of non-terminal-stage deals). | `delta.crm` has no existing service-level aggregate for "tenant-wide open pipeline count/value" to reuse — D-013 exposes per-client relationship scores and per-client deal lists, not a tenant-wide rollup. With no existing counterpart to call, this mirrors D-018/D-019's own "query the shared table directly" convention for a genuinely new, simple aggregate (a count and a filtered sum — not multi-step business logic like burn rate or forecast projection). |
| **3 — `get_executive_summary` takes `now` as a required keyword argument, not an internal `datetime.now()` call** | The router resolves `now` from the real wall clock (`_now()`, mirroring `forecasting/router.py`'s own helper) and passes it in; the service function itself never calls the clock. | Discovered directly while writing `tests/executive/test_service_db.py`: forecasting's `_period_spend` window is `[period_start, now)`, so a service that silently reads the real wall clock makes the current-period-spend and critical-budget assertions **flaky relative to whatever moment the test happens to run** — a usage row seeded a fixed offset before a hardcoded test `_NOW` can land AFTER the real `datetime.now()` if the two clocks disagree by even a few hours, causing `total_current_period_spend_cents`/`budgets_at_critical` to silently read `0`. Requiring `now` as an explicit parameter (D-011's own `forecast_all_budgets(session, now=now, ...)` convention) makes the service pure and deterministic given its inputs, and lets `test_service_db.py` pin a single consistent `_NOW` across both the seeded data and the assertion — exactly the pattern `forecasting`'s own test suite already uses to stay deterministic. |
| **4 — no new table, no migration, no write path** | `delta.executive` contains `schemas.py`, `store.py` (one read function), `service.py` (one compose function), `router.py` (one `GET` route) — no `models.py` additions, no `session.commit()` anywhere in the package. | The task is definitionally a rollup of data three other modules already own and persist; inventing an `executive_summaries` cache table would be premature optimization (a summary this small is cheap enough to compute on every request) and would introduce a second, potentially-stale copy of numbers that already have one authoritative source each. |
| **5 — `delta.executive` is gated by `require_admin` only, not retrofitted with D-017's RBAC** | `executive/router.py`'s router-level dependency is `Depends(require_admin)` — the same break-glass bearer every surface except D-008's dashboards uses. | Mirrors D-018 ADR §2 Fork 6 and D-019 ADR §2 Fork 6's identical reasoning: D-017's RBAC retrofit was deliberately bounded to D-008's dashboards; D-020 is the ninth surface to correctly stay out of that bounded scope. |
| **6 — one summary endpoint, not a dashboard of sub-resources** | `GET /v1/admin/executive/summary?tenant_id=&start=&end=` returns one `ExecutiveSummaryView` with all composed figures. No separate `/executive/spend`, `/executive/forecasts`, `/executive/pipeline` sub-routes. | The whole point of an executive rollup is one screen, one number set, one request — splitting it into N sub-resources would just make the frontend re-implement the composition this service already does, for no benefit (the underlying D-008/D-011/D-013 endpoints already exist independently for anyone who needs the disaggregated view). |
| **7 — mounted on the existing admin app, not a new process** | `GET /v1/admin/executive/summary` on the same D-007 admin app, alongside the other 11 mounted routers. | Same operators, same auth boundary, same trust boundary — mirrors D-008/.../D-019's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **Not a literal rollup "across the OS."** Only D-008 spend, D-011 forecasts, and
  D-013 pipeline are composed — the roadmap's own `Depends on` line, not chargeback
  (D-012), ERP (D-014), PM (D-015), capacity (D-016), invoicing (D-018), or
  integrations (D-019). A future iteration could compose those too; this task
  scopes to the three the roadmap actually named.
- **No caching/materialization.** Every request recomputes the full composition
  live — for a tenant with a very large number of active budgets or CRM deals this
  could become a slow request; no pagination or time-bounding beyond the caller's
  own `start`/`end` window exists on the forecast/pipeline portions today (the
  forecast call itself is bounded to `limit=500` budgets, matching
  `forecasting.router`'s own list cap).
- **No trend/delta vs. a prior period.** Mirrors D-008 ADR's own noted honesty
  boundary (no prior-period comparison built) — `StatTile` on the frontend
  deliberately has no trend arrow for the same reason it doesn't on the D-008
  dashboards page.
- **No cross-tenant/portfolio view.** One `tenant_id` per request, same as every
  other Delta admin endpoint — there is no "all tenants" executive rollup.
- **Single-currency.** Pipeline value is summed only for deals in `DEFAULT_CURRENCY`
  ("USD") — mirrors D-013's own no-FX-conversion pipeline value and D-001's
  no-FX rule; a deal in a different currency is excluded from the sum entirely
  (see `test_pipeline_summary_scoped_to_currency`), not converted.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant leak — a tenant's summary includes another tenant's spend/budgets/pipeline | Every underlying call (`get_summary`, `forecast_all_budgets`, `get_pipeline_summary`) runs inside the caller's own `get_tenant_session(tenant_id)`; RLS makes a foreign-tenant row invisible to each of the three composed queries independently | `test_executive_summary_cross_tenant_isolated`, `test_pipeline_summary_cross_tenant_isolated`, `test_cross_tenant_summary_is_isolated_over_http` |
| A composed figure silently drifts from its owning module's own value (e.g. this rollup re-derives burn rate differently than D-008 does) | Structurally impossible for spend/forecasts: `get_executive_summary` calls D-008's/D-011's own service functions and passes their typed return values straight through — there is no second implementation of burn-rate or forecast-projection math anywhere in `delta.executive` (Fork 1) | code review; `test_executive_summary_composes_spend_forecast_and_pipeline` asserts the composed view's `total_cost_cents`/`burn_rate_cents_per_hour` match what D-008's own summary would report for the identical window |
| `now`-dependent flakiness — current-period-spend/critical-budget figures silently read `0` because the service read a different clock than the test's seeded data | `now` is a required, caller-supplied parameter (Fork 3) — the router is the ONLY place that reads the real wall clock; the service and store are pure given their inputs | `test_executive_summary_composes_spend_forecast_and_pipeline`, `test_executive_summary_counts_critical_budget` (both pin a single `_NOW` for both seeding and assertion; this exact bug was caught live during implementation before merge — see Fork 3) |
| A terminal-stage deal (`won`/`lost`) inflates the "open pipeline" count/value | `get_pipeline_summary`'s `open_deal_count`/`open_pipeline_value_minor_units` queries filter `deals.c.stage.notin_(_TERMINAL_STAGES)` | `test_pipeline_summary_excludes_terminal_deals` |
| A deal with a null `value_minor_units` (a `lead`-stage deal with no value yet) silently breaks the sum or is double-counted | `func.coalesce(func.sum(...), 0)` — a null-value deal is counted in `open_deal_count` but contributes `0`, never `NULL`, to the sum | `test_pipeline_summary_excludes_null_value_deals_from_sum` |
| SQL injection via any executive-package query | `store.py`'s only query is a parameterized SQLAlchemy Core statement — no raw string-interpolated SQL | code review |
| Auth bypass on the one new route | Router-level `dependencies=[Depends(require_admin)]` | `test_get_summary_missing_bearer_is_401` |
| `end <= start` accepted as a valid (empty or inverted) window | `ExecutiveSummaryQuery`'s `model_validator` rejects `end <= start`, mirroring D-008's own `DashboardQuery` validation | `test_executive_summary_query_rejects_end_before_start`, `test_executive_summary_query_rejects_equal_start_end`, `test_get_summary_rejects_end_before_start_over_http` |
| Naive (non-UTC-aware) `start`/`end` silently misinterpreted | `require_aware_utc` rejects a naive datetime at the schema layer, same helper every other Delta window-query schema uses | `test_executive_summary_query_rejects_naive_start` |

## 5. Verification

- `black --check .` / `ruff check .` clean on the FULL repository (not just
  `src/delta/executive`).
- New `tests/executive/` suite: 18 tests — 5 pure schema-validation tests
  (`test_schemas.py`, no DB/I/O), 5 DB-backed store tests (`test_store_db.py`,
  including terminal-deal exclusion, null-value handling, currency scoping, and
  cross-tenant isolation), 4 DB-backed service tests (`test_service_db.py`,
  covering the full composed rollup, the zero-state tenant, critical-budget
  counting, and cross-tenant isolation), 4 non-stubbed HTTP e2e tests
  (`test_router_e2e.py` — real ASGI app, real auth, real DB).
- Full existing Delta suite green (895 passed, 15 skipped) — zero regressions.
- No migration to apply (Fork 4) — verified zero new/modified tables via review of
  `persistence/models.py` (unchanged by this task).
- Frontend: `tsc --noEmit` clean, `next lint` clean (0 warnings/errors on all new/
  modified files), `next build` succeeds with `/executive` registered as a dynamic
  route. Live browser smoke test performed against a real running backend with real
  data entered through the UI's own upstream modules: seeded a CRM client + deal via
  direct backend calls, logged in via the break-glass token, loaded the (previously
  unset) executive page, confirmed the window-picker prompt state, clicked the "Last
  24h" preset, confirmed all three composed sections (Spend/Budget forecasts/
  Pipeline) rendered with the expected client count (1), open deal count (1), and
  pipeline value ($5.0K) — cross-checked against a direct follow-up call to
  `GET /v1/admin/executive/summary` returning the identical figures.
- Independent security-auditor review: pending, findings will be recorded in
  `docs/audit/d-020-security-audit.md`.

## 6. Alternatives considered

- **Re-deriving burn-rate/forecast math directly against `ledger_entries`/
  `budget_definitions` instead of calling D-008/D-011's services.** Rejected
  (Fork 1): two independent implementations of the same formula are a drift risk a
  pure rollup has no reason to accept — reusing the tested, owning module's own
  service function is strictly safer and simpler.
- **A cached/materialized `executive_summaries` table refreshed on a schedule.**
  Rejected (Fork 4): no background worker infrastructure exists in Delta today for
  this, and a live-computed rollup is cheap enough (three bounded queries) that a
  cache would add staleness risk for no measured performance problem.
- **Retrofitting D-017's RBAC (`tenant_auditor` role) onto this endpoint, since an
  executive summary is exactly the kind of read-only report an auditor role would
  want.** Considered and rejected for this task (Fork 5): D-017's ADR deliberately
  bounded that retrofit to D-008's dashboards as the FIRST RBAC-gated surface; widening
  it here would be scope creep beyond D-020's own dependency line. A follow-up task
  extending D-017's RBAC to this and other read surfaces is a reasonable, separate
  future item.
- **Splitting the rollup into three sub-resources (`/executive/spend`,
  `/executive/forecasts`, `/executive/pipeline`).** Rejected (Fork 6): those three
  views already exist as D-008/D-011/D-013's own endpoints; an executive dashboard
  splitting into the same three calls the frontend would otherwise make directly
  defeats the purpose of a single composed rollup.
