# ADR-0008 — Delta Live Cost-to-Value Dashboards

- **Status:** Proposed (awaiting human approval — STEP 1 gate)
- **Date:** 2026-07-07
- **Task:** D-008 (Live cost-to-value dashboards) · Builder: frontend
- **Builds on:** D-003 (`persistence/balances.py` read primitives, `ledger_entries`), D-004
  (`ingest/posting.py` — the two-leg posting shape these aggregates depend on), D-007 (the admin
  app/auth/console this task extends rather than duplicates)
- **Delta ADR head is 0007; this is 0008.**

---

## 1. Context — honest scope note

The roadmap describes D-008 in one line: "Real-time spend, burn rate, top spenders,
cost-per-request, cost-per-outcome. Dashboards configurable to client/team-set parameters." Three
of those four figures map directly onto the D-003 ledger; the fourth does not, and that gap is
stated here rather than implied away (banked rule #14):

**"Cost-per-outcome" is NOT built.** Delta has no "outcome" domain concept anywhere in its model
— no success/failure flag, no task-completion signal, nothing an aggregate could divide cost by.
That concept, if it ever exists, lives on Sentinel's side of the boundary (it would require
Sentinel to emit an outcome signal Delta doesn't receive today) or a future Delta feature that
doesn't exist yet. This ADR ships **cost-per-request** (spend / request count) instead, and the
UI/API both say "request," never "outcome."

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — one admin app, not two** | The dashboards router (`delta.dashboards.router`) is mounted into the SAME FastAPI app D-007 already built (`allocation_admin.app.create_app`), not a second process/port. | Same operators, same break-glass bearer, same trust boundary — a second app would duplicate auth/settings/health-check plumbing for no isolation benefit. The app's docstring and title were updated to say so explicitly rather than leaving `allocation_admin` misnamed for a surface that now serves two features. |
| **2 — read-only, zero new migration** | Dashboards are pure `SELECT`/`GROUP BY` aggregates over the existing `ledger_entries` table (D-003). No new table, no new grant, no new RLS policy. | `persistence/balances.py`'s own docstring already named this: "these are the primitives... the burn-rate dashboards (D-008) build on." The read primitives were deliberately built ahead of this task; D-008 adds grouping/bucketing on top, not a new persistence layer. |
| **3 — spend = the debit leg only** | Every query filters `direction = 'debit'`. Summing both legs of a balanced transaction nets to zero; summing all directions indiscriminately double-counts. | D-004's `posting.py` posts exactly one DEBIT (the tenant's expense account) and one CREDIT (a contra account) per usage event, both carrying identical attribution — the debit leg is unambiguously "spend." This assumes every debit-direction row today is a usage-driven expense entry (true as of D-004 through D-007 — no other Delta feature posts a debit yet); a future feature posting a non-usage debit would need explicit exclusion here, not silent inclusion. Documented verbatim in `store.py`'s module docstring so the next feature that adds a debit-direction posting sees the assumption before breaking it. |
| **4 — window + scope are request parameters, not stored config** | `DashboardQuery` takes `tenant_id`, `start`, `end`, and optional `team_id`/`project_id`/`agent_id` on every call — "client/team-set parameters" are query-time, not a saved-dashboard-config entity. | Leanest STEP-0 fork (banked rule #13): a saved-dashboard-configuration model is real future scope (arguably D-008's own vision-tier successor) but nothing in the codebase needs it today, and building it speculatively would be scope creep into a feature nobody asked for yet. |
| **5 — a bounded window, not unbounded history** | `DashboardQuery` rejects a window wider than 400 days (`_MAX_WINDOW_DAYS`). | Mirrors D-007's list-pagination guard (`docs/audit/d-007-security-audit.md` finding #1): an operator must not be able to force an unbounded full-history table scan. Combined with the bucket granularity, the time-series endpoint's response size is bounded by construction — at most `window_days × 24` rows for an hourly bucket, never unbounded by data volume the way an un-windowed list query would be. |
| **6 — `group_by` can never equal a pinned scope filter** | `TopSpendersQuery` rejects (422) a request where `group_by` names a dimension that is ALSO an active `team_id`/`project_id`/`agent_id` scope filter. | Grouping by a dimension you've already pinned to one value produces a meaningless one-row "ranking" — reject the no-op request explicitly (clear 422) rather than silently return a degenerate result the caller has to notice is meaningless. The frontend mirrors this by only ever linking valid group-by/scope combinations (`page.tsx`'s `resolveGroupBy` + the top-spenders pill filter), so an operator never reaches the 422 by clicking through the UI — only a direct API call can. |
| **7 — a display-only compact formatter never loses precision below $1,000** | `formatMinorUnitsCompact` (frontend) falls back to full-cent `formatMinorUnits` under $1,000 rather than always using `Intl`'s compact notation (which would round `$12.34` to `$12.3`). | Caught by the frontend's own unit test while building this: a financial admin tool silently rounding away real cents on everyday-sized figures is a precision regression, not a cosmetic one — worth the extra branch to avoid. |
| **8 — the time-series line breaks across gaps, never interpolates** | The backend returns only buckets with at least one entry (a zero-spend bucket is omitted, not returned as an explicit zero); the frontend chart breaks its line wherever the gap between two adjacent points exceeds one bucket step, instead of drawing a straight line across the gap. | A straight line across a multi-bucket gap would visually claim spend happened during a quiet period that had none — an honest chart shows a gap, not a smoothed lie (dataviz skill, "text never wears the data color" cousin: a mark must not assert something the data doesn't). Zero-filling every bucket server-side would also fix this but adds real complexity (explicit range generation) for a display concern the frontend can solve on its own; noted here as the deliberately-not-built alternative. |

## 3. Architecture

### 3.1 Backend — `Delta/src/delta/dashboards/`

```
store.py     SQL aggregates over ledger_entries: spend_summary, spend_time_series, top_spenders.
             ScopeFilter (team/project/agent, all optional) narrows every query identically.
schemas.py   DashboardQuery (shared window+scope validation) -> TimeSeriesQuery / TopSpendersQuery
service.py   query -> store call -> response view (no logic beyond that mapping)
router.py    GET /v1/admin/dashboards/{summary,timeseries,top-spenders}, reuses D-007's
             require_admin (no new auth surface)
```

Every route opens `get_tenant_session(tenant_id)` for the caller-supplied tenant, exactly like
every D-007 route — RLS is the isolation boundary, not the admin bearer (which authenticates the
operator, not a tenant scope).

### 3.2 Frontend — `Delta/frontend/src/app/(admin)/dashboards/`

Server component reading `searchParams` (tenant, window, scope, group-by) and calling
`adminApi.{getSummary,getTimeSeries,getTopSpenders}` directly (server-side, same pattern as the
D-007 allocations page) — no new BFF-proxy usage beyond adding `"dashboards"` to `bff.ts`'s
`ALLOWED_ROOTS` for parity/future-proofing (the proxy route itself is not on the hot path for this
page, same as D-007). Renders: four stat tiles (total spend, requests, cost/request, burn rate),
an SVG time-series line chart (single hue, hover crosshair + tooltip, direct end-label, no legend
needed for one series — dataviz skill), a ranked top-spenders bar list, and a plain data table
mirroring the chart's own points (every value the chart shows is also reachable without hovering).

## 4. Tenant isolation

Identical mechanism to D-007 (ADR-0007 §4): every route resolves `get_tenant_session(tenant_id)`
for the tenant the caller explicitly supplies; RLS is enforced by the `delta_app` (NOBYPASSRLS)
role regardless of the admin bearer's scope.

## 5. Threat model (vectors -> tests)

| # | Vector | Mitigation | Test |
|---|---|---|---|
| 1 | Cross-tenant spend data read | RLS FORCE + NULLIF predicate on `ledger_entries` (unchanged from D-003) | `test_cross_tenant_spend_is_isolated`, `test_cross_tenant_summary_is_isolated_over_http` |
| 2 | Double-counting spend (summing both ledger legs) | Every query filters `direction = 'debit'` | `test_spend_summary_counts_debit_leg_once` |
| 3 | Unbounded window forces a full-history scan | `DashboardQuery` rejects windows over 400 days | `test_window_exceeding_max_days_rejected` |
| 4 | `group_by` naming a pinned scope filter returns a meaningless one-row ranking silently | Rejected as 422 (fork 6) | `test_group_by_same_as_pinned_scope_rejected`, `test_top_spenders_group_by_pinned_scope_is_422` |
| 5 | Naive/inverted window accepted, producing a nonsensical or empty-looking result silently | `end` must be strictly after `start`; both must be timezone-aware UTC | `test_end_must_be_after_start`, `test_naive_datetime_rejected`, `test_inverted_window_is_422` |
| 6 | Missing/wrong admin bearer reaches a tenant-scoped route | `require_admin` (D-007, unchanged) fail-closed 401 | `test_summary_missing_bearer_is_401` |
| 7 | `group_by` string reaches raw SQL construction unvalidated | Constrained by a Pydantic `Literal["team_id","project_id","agent_id"]` before `getattr(ledger_entries.c, group_by)` ever runs; FastAPI/Pydantic reject any other value at the request boundary | (structural — no attacker-controlled string reaches `getattr` unvalidated; covered indirectly by every `top_spenders` test using only the three real values) |

## 6. Honesty boundary (what D-008 is NOT)

- **Not** cost-per-outcome (§1) — cost-per-request only, and named that way everywhere (API field,
  UI label).
- **Not** a saved/configurable dashboard entity — window and scope are per-request parameters,
  reset on navigation (fork 4).
- **Not** billing-grade — every figure here is the same *client-side cost estimate* the rest of
  Delta already is (`cost_estimate_cents` recorded from Sentinel, never Delta's own pricing);
  `cost_per_request_cents` is additionally a derived float (a ratio), never itself a monetary
  amount that should be summed or re-persisted.
- **Not** wired into `docker compose up` — same as D-007 (ADR-0007 fork 9); no Delta HTTP surface
  is yet, that is D-010's job.
- **Not** zero-filled time-series — a quiet bucket is an omitted row, not an explicit zero; the
  frontend renders that honestly as a line break, not an interpolated smooth line (fork 8).

## 7. Consequences

- **Positive:** exercises the D-003 read-primitive seam exactly as its own docstring anticipated;
  adds zero new migration, zero new grant, zero new auth surface — the smallest possible D-008
  that still delivers three of the roadmap's four named figures honestly.
- **Negative / accepted:** cost-per-outcome is simply not available until Delta (or Sentinel)
  gains an outcome signal to divide by (§1); the time-series endpoint's per-request row count is
  bounded by window×bucket-granularity (fork 5) rather than by an explicit row LIMIT the way
  D-007's list endpoints are — accepted because the bound is already structural (at most
  `400 days × 24 hours` = 9,600 rows for the widest legal request), not because a LIMIT was
  considered and rejected.
