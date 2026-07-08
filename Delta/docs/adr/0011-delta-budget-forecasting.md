# ADR-0011 — Predictive Budget Forecasting (Current-Rate Projection + Advisory Recommendations)

- **Status:** Accepted
- **Date:** 2026-07-08
- **Task:** D-011 (Predictive SaaS/cloud budget optimization) · Builder: orchestration-hooks
- **Depends on:** D-003 (the ledger every spend figure comes from), D-008 (the dashboards
  aggregate queries this task reuses rather than duplicates)
- **Builds on:** D-005's soft-warning-threshold pattern (`budget_engine.decision`/`warnings`)
  — extended from "already crossed" to "projected to cross."
- **Supersedes:** nothing. Adds a new `delta.forecasting` package and two small read-only
  helpers to `budget_engine.definitions`; does not alter any D-001…D-010 runtime behavior,
  contract, or persistence schema (zero new migration).

## 1. Context

The roadmap's literal text for D-011 is: *"Predictive modeling for optimizing SaaS
procurement and cloud budget utilization (burn-rate forecasting + optimization
recommendations)."* Taken at face value, "predictive modeling" could imply a trained
statistical or machine-learning model. Before writing any code, a repo-wide search
confirmed **no forecasting, trend, regression, or predictive-modeling feature exists
anywhere in the Anoryx ecosystem today** — not in Sentinel, not in the Orchestrator, not in
Rendly. There is no reference implementation to mirror, no training-data pipeline, no
validation/backtesting harness, and no dedicated ML review process in this repo. Building an
actual trained model here would be the same kind of unreviewed, first-of-its-kind
ecosystem-first move that D-010's ADR explicitly declined for Vault/mTLS — this ADR makes
the analogous honest call for "predictive modeling."

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — current-rate projection, not a regression/ML model** | Forecast a budget period's end-of-period spend by holding the CURRENT period's own average rate (`spend_so_far_cents / hours_elapsed`) constant and projecting it across the remaining hours in the period — the exact same "flat average" concept D-008's `burn_rate_cents_per_hour` already uses (see `dashboards/store.py:62-64`), extended from "the current rate" to "the current rate, held constant to project period-end spend." **Not** a least-squares fit over bucketed daily spend. | With as few as 2-3 daily buckets (common early in a period), a fitted regression slope is extremely sensitive to one noisy point and can extrapolate a wild, misleading number. A flat average over the ENTIRE elapsed period is far more robust to a single spike or lull, requires no bucket-densification logic, and is directly traceable to a number an operator already trusts (D-008's own burn rate). Simpler is also more honest: there is no "curve" being fit, just an average rate, and the API says so explicitly (`method: "current_rate_projection_v1"`, fork 6). |
| **2 — reuses `budget_engine.spend.scope_spend_cents`, not a new query** | Every spend figure in a forecast (current-period spend, and the two elapsed-time halves used for trend direction) comes from the SAME authoritative net-expense-balance query the budget engine itself uses for enforcement (ADR-0005 §3.1) — not a re-derivation. | A forecast can never disagree with enforcement about "how much has been spent so far," because it asks the identical question of the identical ledger data. Two independent "current spend" implementations (one for enforcement, one for forecasting) would be a drift risk with no benefit. |
| **3 — trend DIRECTION only, never a second rate driving the number** | A qualitative `trend_direction` (`"rising"`/`"falling"`/`"flat"`) is computed by comparing the first and second halves of the elapsed period (two more calls to the same `scope_spend_cents` — no bucketing, no regression), gated behind a 20% band to avoid noise-driven flips, and gated behind a minimum 2 hours elapsed. It is surfaced as an informational recommendation (`RISING_TREND`) — it never feeds into `burn_rate_cents_per_hour` or the projected total. | Gives the roadmap's "predictive" framing real qualitative content (a genuine week-over-week-style signal) without letting a second, noisier rate silently override the primary, robust flat-average projection that actually drives the exceedance forecast. |
| **4 — "optimization recommendations" reuses D-008's `top_spenders`, not new analytics** | The one genuinely new "where to look to cut cost" signal (`SPEND_CONCENTRATION`) calls D-008's existing, tested `dashboards.store.top_spenders` unchanged — one level finer than the budget's own scope (tenant→team, team/project→agent), flagged when a single group exceeds 50% of spend. Not offered for AGENT-scoped budgets (already Delta's finest granularity — nothing finer to break down). | "Optimization recommendation" does not require new modeling to be honest and useful — pointing at where spend concentrates is a real, actionable signal a FinOps operator already needs, and D-008 already computes it correctly. Reusing it here is the same "don't build unused things" discipline as everywhere else in this repo. |
| **5 — recommendations are deterministic, threshold-based, and advisory-only** | Five recommendation codes (`INSUFFICIENT_DATA`, `NO_COST_CAP`, `ALREADY_OVER_CAP`, `SOFT_THRESHOLD_CROSSED`, `PROJECTED_TO_EXCEED`) plus two informational ones (`RISING_TREND`, `SPEND_CONCENTRATION`) — all pure functions of already-computed numbers, all advisory text returned in an HTTP response. `ALREADY_OVER_CAP`/`SOFT_THRESHOLD_CROSSED` reuse `budget_engine.decision.is_over_cost_cap`/`soft_warning_band` directly (the exact same integer comparisons enforcement uses). Nothing in this module writes to the outbox, enforcement state, or the audit chain — mirrors `warnings.py`'s own invariant ("a soft warning can never become a hard block"). | A forecast is worthless if it can silently disagree with what the enforcement engine would actually do. Reusing the exact decision functions (not re-implementing the same `>`/`>=` comparison a second time) makes that structurally impossible, not just tested-to-be-true today. |
| **6 — explicit, versioned method tag; float clearly labeled as an estimate** | The response always carries `method: "current_rate_projection_v1"` (a literal, not a free-text description) and `projected_period_end_spend_cents`/`burn_rate_cents_per_hour` are typed `float`, never `int` — an explicit signal these are estimates, not the integer-cents enforcement path (`budget_engine.decision` stays strictly integer throughout; ADR-0005's own "no float anywhere in the spend-vs-cap path" invariant is untouched — the float projection is never fed back into a real decision). A future different method gets a NEW literal, never a silent redefinition of this one. | Mirrors D-008's own honest framing of `burn_rate_cents_per_hour`/`cost_per_request_cents` as floats while `current_period_spend_cents` stays integer. Names the technique so nobody downstream mistakes "the current rate held flat" for a validated statistical or ML forecast. |
| **7 — no persisted state, no migration** | Every forecast is computed live from `budget_definitions` (D-005) + `ledger_entries` (D-003) at request time — nothing is stored, cached, or historized. | Mirrors D-008's own "zero new migration" decision (pure read aggregates). A forecast is a point-in-time view; persisting historical forecasts (to later ask "was the forecast right?") is real future work this ADR does not claim to deliver — see Honest deferrals. |
| **8 — mounted on the existing admin app, not a new process** | `GET /v1/admin/forecast/budgets[/{budget_id}]`, same `require_admin` break-glass bearer auth, same `allocation_admin/app.py` FastAPI instance D-007/D-008/D-009 already share. | Same operators, same auth, same trust boundary — mirrors D-008/D-009's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No trained/validated statistical or ML model.** The "current-rate projection" is
  deliberately simple, deterministic arithmetic — not a regression, not a time-series model
  (ARIMA/Prophet/etc.), not anything requiring a training set or a backtest. There is no
  precedent anywhere in this ecosystem to build one against, and doing so unilaterally here
  — with no dedicated review cycle for a modeling approach — would be exactly the kind of
  scope-widening-under-ambiguity this task's operating procedure is instructed to avoid.
- **No forecast history / accuracy tracking.** Nothing persists a forecast to later compare
  against what actually happened. A `forecast_accuracy` feature (store predictions, compare
  to realized spend) is real, valuable future work this task does not claim to deliver.
- **No cross-budget / cross-tenant portfolio view.** `GET /v1/admin/forecast/budgets` lists
  one tenant's own budgets (RLS-confined, capped at 100 — mirrors D-007/D-008's list caps);
  there is no "which of my tenants is trending worst" rollup.
- **Forecasting is meaningful only once enough time has elapsed in the period.** Under one
  hour elapsed, `INSUFFICIENT_DATA` is returned honestly rather than a number extrapolated
  from near-zero data — this is a real limitation of "current-rate projection," not a bug:
  a budget's period resetting is itself the reason there is nothing to project yet.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Forecast disagrees with real enforcement about current spend | `_period_spend` calls the SAME `budget_engine.spend.scope_spend_cents` enforcement uses — no second "spend" implementation | `test_forecast_current_period_spend_and_burn_rate` |
| A float projection leaks into an actual enforcement decision | `ALREADY_OVER_CAP`/`SOFT_THRESHOLD_CROSSED` call `decision.is_over_cost_cap`/`soft_warning_band` directly on the INTEGER `current_period_spend_cents`, never the float projection; `PROJECTED_TO_EXCEED` is advisory text only, no state/outbox write | `test_already_over_cap_is_critical_and_skips_soft_threshold`; grep confirms no `forecasting` import anywhere under `budget_engine/evaluator.py`, `outbox.py`, or `state.py` |
| Cross-tenant budget/spend leak | Every query runs on the caller's tenant-scoped (RLS) `AsyncSession`; `get_budget` returns `None` for another tenant's id (indistinguishable from not-existing) | `test_forecast_cross_tenant_isolation`, `test_cross_tenant_forecast_is_isolated_over_http` |
| Noisy/sparse data produces a wildly wrong "rising/falling" label | 20% band + 2-hour minimum elapsed time before a trend direction is computed at all | `test_trend_within_20_percent_band_is_flat_not_noise`, `test_no_trend_direction_before_two_hours_elapsed` |
| A budget with no cost cap gets a fabricated exceedance forecast | `NO_COST_CAP` recommendation returned instead, no projection numbers computed against a nonexistent cap | `test_forecast_no_cost_cap` |
| `GET /v1/admin/forecast/budgets` query amplification (independent security review) | Each budget forecast is up to 4 sequential DB round-trips (current spend, two half-window spends, `top_spenders`) — a bare `MAX_LIST_LIMIT = 100` (D-007/D-008's own cap) would allow ~400 queries per single request, well past what D-008's own 1-query-per-row list endpoints cost. `router.py`'s `list_forecasts` uses a dedicated, smaller `_MAX_LIST_FORECAST_BUDGETS = 25` (not `definitions.list_budgets`'s general-purpose default of 100, which other, cheaper callers may still use) | code review — bounded to ≤100 queries/request, same order of magnitude as D-008's worst case |
| `SPEND_CONCENTRATION` percentage misleading when a reversal exists in the period (independent security review) | The numerator (`dashboards.store.top_spenders`, gross debit-direction rows) and denominator (`budget_engine.spend.scope_spend_cents`, net debit-minus-credit expense balance) use different accounting bases — nominally could exceed 100%. Clamped to `min(100.0, ...)` and worded "approximately N%," never claimed as enforcement-grade precision. No security/cross-tenant impact either way (both queries run on the same RLS-confined session and budget scope) — this was a correctness/wording issue, not an isolation one. | code review; `test_spend_concentration_flagged_above_50_percent_share` still passes with the reworded, clamped message |
| `AGENT`-scoped budget gets a meaningless "concentration" breakdown | `_CONCENTRATION_GROUP_BY` has no entry for `BudgetScope.AGENT` — the recommendation is silently omitted, not fabricated | `test_forecast_agent_scoped_budget_has_no_concentration_recommendation` |

## 5. Verification

- `black --check` / `ruff check .` clean.
- New `tests/forecasting/` suite: 39 tests — 25 pure unit tests (`test_projection.py`,
  `test_recommendations.py`, no DB/no I/O) + 9 DB-backed service tests (real budgets, real
  ledger rows via the D-004 posting path, real RLS) + 5 non-stubbed HTTP e2e tests (real
  ASGI app, real auth, real DB).
- Full existing Delta suite green (535 passed, 9 skipped) — zero regressions, zero changes
  to any D-001…D-010 file's runtime behavior (only two additive, backward-compatible read
  helpers added to `budget_engine/definitions.py`: `get_budget`, `list_budgets`).
- DB-backed tests pin an explicit `now` (never the real wall clock) for determinism; the
  five router e2e tests cannot do this (the router resolves `now` from the real clock,
  mirroring every other Delta admin endpoint — none accept a client-supplied time), so they
  seed usage a few minutes in the past (mirrors `budget_engine`'s own `_recent_ts()`
  e2e-test pattern) — an accepted, pre-existing tiny calendar-boundary risk, not a new one
  this task introduces.

## 6. Alternatives considered

- **Fit a linear regression over daily spend buckets (the roadmap's literal "predictive
  modeling" reading).** Rejected (Fork 1): with a handful of noisy daily points, a fitted
  slope is unstable and can produce a misleading extrapolation; the flat-average approach is
  simpler, more robust, and traceable to a number D-008 already established as trustworthy.
- **Build a real trained/validated forecasting model (ARIMA, exponential smoothing, or an
  actual ML model).** Rejected for the same reason D-010 rejected building real Vault/mTLS
  unilaterally: no prior ecosystem implementation to build from or review against, no
  training-data/backtest story, and doing so under an unattended, single-PR run without a
  dedicated modeling review cycle would be exactly the kind of scope-widening this run's
  procedure is instructed to avoid.
- **Persist forecasts for later accuracy tracking.** Rejected for this task — real, valuable
  future work, but a genuinely separate feature (needs its own schema/migration/retention
  policy) named honestly as a deferral rather than half-built here.
