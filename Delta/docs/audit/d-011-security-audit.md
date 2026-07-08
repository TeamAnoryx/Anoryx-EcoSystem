# D-011 Security Audit — Predictive Budget Forecasting

- **Date:** 2026-07-08
- **Scope:** `Delta/src/delta/forecasting/` (the entire new package), the two new read-only
  functions added to `Delta/src/delta/budget_engine/definitions.py` (`get_budget`,
  `list_budgets`), the one new router mount in `Delta/src/delta/allocation_admin/app.py`,
  `Delta/tests/forecasting/`, and `Delta/docs/adr/0011-delta-budget-forecasting.md` (the
  design record, cross-checked against the actual shipped code).
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per
  banked process rule #3 — re-run against the code, not implementer-self-verified).
- **Verdict:** **CLEAN** — no High or Critical findings. Three Low findings; all three
  fixed on this branch before merge.

## Note on tooling

Semgrep's registry rulesets could not be fetched in the audit environment (the egress
proxy denies `CONNECT` to `semgrep.dev` — the same known limitation recorded in every
prior audit this session; see `docs/audit/d-010-security-audit.md`). This pass is manual
dataflow analysis, tracing every claim in the ADR back to the actual source, per the same
accepted precedent. `delta-ci.yml`'s `quality` job's Semgrep step runs for real in CI
(registry reachable there) and remains the authority of record for SAST on this PR.

## What was actively tried and found sound

- **Cross-tenant leakage.** `definitions.get_budget`/`list_budgets` run on the caller's
  RLS-confined tenant session; every downstream spend/top-spender query in `service.py`
  reuses that same session and the looked-up `budget.tenant_id` (which, by RLS
  construction, always equals the session's own GUC tenant — it cannot diverge). The
  query-string `tenant_id` drives the session's GUC directly (`router.py`); it cannot
  influence which rows are visible independent of RLS. `get_budget` returns `None`
  identically for "doesn't exist" and "belongs to another tenant" (no existence leak).
  Verified by `test_forecast_cross_tenant_isolation`,
  `test_cross_tenant_forecast_is_isolated_over_http`.
- **Float projections never reach an enforcement decision.** `recommendations.py` feeds
  only the INTEGER `projection.current_period_spend_cents` into
  `budget_engine.decision.is_over_cost_cap`/`soft_warning_band` (the exact functions
  enforcement itself uses) — the `float` projection (`burn_rate_cents_per_hour`,
  `projected_period_end_spend_cents`) is only ever interpolated into advisory message
  text. Confirmed via full-package review: nothing under `delta/forecasting/` calls
  `.commit()`, writes to the budget-publish outbox, enforcement state, or the D-009 audit
  chain. The ADR's "never fed back into enforcement" claim holds.
- **Division-by-zero / degenerate time math.** Every division in `projection.py` is
  guarded: `burn_rate_cents_per_hour` only computed once `elapsed_hours >=
  MIN_ELAPSED_HOURS_FOR_PROJECTION` (1.0); the first/second-half trend split only computed
  once `elapsed_hours >= _MIN_ELAPSED_HOURS_FOR_TREND` (2.0); `exhaustion_at` guarded by
  `burn_rate_cents_per_hour <= 0` and `current_period_spend_cents >= cap_cost_cents`
  returning `None` before ever dividing. `elapsed_hours`/`remaining_hours` are both
  clamped via `max(0.0, ...)`, and `period_start <= now < period_end` holds by
  construction (`periods.period_start`/`period_end` are derived FROM `now` itself — `now`
  can never precede its own period's start).
- **Query-string `budget_id` handling.** `definitions.get_budget` uses a parameterized
  SQLAlchemy equality predicate — no SQL-injection surface regardless of the string's
  shape. Any malformed/non-matching value yields `None` → HTTP 404, indistinguishable
  from a genuine cross-tenant id (no existence leak either way). Any unexpected driver
  error is caught by the app-wide failsafe handler (`allocation_admin/app.py`), returning
  a generic 500 with no internals leaked.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | Low | `forecasting/service.py` (`forecast_all_budgets`) | Each budget forecast is up to 4 sequential DB round-trips (current-period spend, two half-window spends for trend direction, `top_spenders`). The original `GET /v1/admin/forecast/budgets` used the general-purpose `definitions.list_budgets` default cap of 100, which would permit up to ~400 sequential queries for a single authenticated request — well past D-008's own list endpoints (1 query per row). Bounded blast radius (a single trusted break-glass token, not a cross-tenant or external-attacker path), so this was self-inflicted operator-load risk, not an isolation or auth bypass. | **Fixed.** `router.py`'s `list_forecasts` now passes a dedicated, smaller `_MAX_LIST_FORECAST_BUDGETS = 25` (not `definitions.list_budgets`'s own general default, which other, cheaper callers may still use unchanged) — caps a single request's worst case at 100 queries, back in the same order of magnitude as D-008's own worst case. ADR-0011 §4 threat table updated to name the amplification explicitly rather than only accounting for the row cap. |
| 2 | Low | `forecasting/recommendations.py` (`SPEND_CONCENTRATION`) | The concentration ratio's numerator (`dashboards.store.top_spenders`, sums GROSS debit-direction rows) and denominator (`budget_engine.spend.scope_spend_cents`, NET debit-minus-credit expense balance) use different accounting bases. When a reversal exists within the period, the computed share can nominally exceed 100% or otherwise misstate concentration — a correctness/wording defect in advisory text, not a security or cross-tenant issue (both queries run on the same RLS-confined session and the same budget scope; `group_key` is a tenant-internal id, JSON-encoded, no injection risk). | **Fixed.** Display value clamped to `min(100.0, ...)`; message reworded to "accounts for approximately N%" rather than implying precision the two mismatched accounting bases don't support. ADR-0011 §4 updated to name the basis mismatch explicitly. |
| 3 | Low | `forecasting/router.py` (`get_forecast`) | `budget_id` was typed as a bare `str` path parameter, unlike `tenant_id: TenantId` (a constrained UUID type) — a convention divergence. No exploit was found (parameterized query, RLS-safe 404 either way, generic 500 on any unexpected error), so this was optional per the reviewer, but fixed anyway for consistency and to return a more correct 422 on malformed input rather than a 404 that's indistinguishable from "not found." | **Fixed.** `budget_id` now typed `identifiers.UuidStr` (the same constrained-UUID type `tenant_id`/`team_id`/etc. already use across the codebase) — malformed input now gets FastAPI's standard 422, matching every other Delta identifier-shaped path/query parameter. |

## Threat model cross-reference

See `docs/adr/0011-delta-budget-forecasting.md` §4 for the full vectors-to-mitigations-to-tests
table this audit validated against (spend-source consistency with enforcement, float/integer
boundary discipline, cross-tenant isolation, noisy-trend-direction false positives, no-cost-cap
handling, list-endpoint resource amplification, agent-scope concentration omission).

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-011 forecasting surface listed under Scope above. It does not
re-audit `budget_engine.spend`/`decision`/`periods` (unchanged, already audited at
`docs/audit/d-005-security-audit.md`) or `dashboards.store.top_spenders` (unchanged, already
audited at `docs/audit/d-008-security-audit.md`) — D-011 calls both unmodified and this review
confirmed it does so correctly, not that either function is independently re-verified here. Per
ADR-0011 §3, "current-rate projection" is deliberately simple, deterministic arithmetic, not a
trained or validated statistical/ML model — this review assessed it as such, not against any
accuracy/forecasting-quality bar a real predictive model would need to clear.
