# ADR-0012 — Departmental Chargeback/Showback + Trailing-Average Anomaly Detection

- **Status:** Accepted
- **Date:** 2026-07-08
- **Task:** D-012 (Chargeback / showback + anomaly detection) · Builder: frontend + analytics
- **Depends on:** D-003 (the ledger every spend figure comes from), D-008 (the dashboards
  aggregate query — `dashboards.store.top_spenders` — this task reuses rather than duplicates)
- **Builds on:** D-006's kill-switch `anomalous_reason()` (a fixed absolute ceiling on a single
  transaction's cost) and D-011's forecasting `SPEND_CONCENTRATION` recommendation — both are a
  DIFFERENT shape of "anomaly" than this task's spend-pattern-over-time signal; neither is reused,
  only referenced/contrasted below.
- **Supersedes:** nothing. Adds a new `delta.chargeback` package and one new router mount to
  `allocation_admin/app.py`; does not alter any D-001…D-011 runtime behavior, contract, or
  persistence schema (zero new migration).

## 1. Context

The roadmap's literal text for D-012 is: *"Departmental chargeback/showback reports +
anomalous-spend detection."* Two distinct capabilities, both read-only over the existing D-003
ledger:

1. **Chargeback/showback** — attribute cost to a department (team/project/agent) over a window,
   with each group's share of total spend. Purely descriptive; no new query shape (D-008's
   `top_spenders` already computes exactly this).
2. **Anomalous-spend detection** — flag a group whose current spend looks unusual relative to its
   own recent history. This is the part that needs a genuine design decision: what counts as
   "unusual," and how is it computed without a training set, a statistics library, or an
   ecosystem precedent for real forecasting/ML (D-011's ADR already established there is none).

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — trailing-average RATIO, not z-score/stddev/ML** | A group's anomaly signal compares its CURRENT window's spend to its own trailing N-period baseline AVERAGE spend (`current / (baseline_total / baseline_periods)`). `SPEND_SPIKE` fires when that ratio `>= 3.0x` (default) AND current spend clears a `$10` floor (avoids noise on near-zero spenders). `NEW_SPENDER` fires when the baseline average is zero (no prior spend) and current spend clears the same floor. **Not** a z-score/standard-deviation approach, and not any trained/validated statistical or ML model. | Same reasoning D-011's ADR §1 already established for this ecosystem: no forecasting/ML precedent exists anywhere in Sentinel, the Orchestrator, or Rendly to build against, and small per-period sample sizes (a handful of daily buckets) make stddev-based methods unstable — one noisy day inflates or deflates the variance enough to flip a flag. A ratio against a trailing average is simple, deterministic, explainable to an operator in one sentence, and directly analogous to D-011's own "flat average, held constant" simplicity argument. |
| **2 — exactly 2 DB queries total, never N+1 per group** | `get_anomaly_report` issues exactly 2 queries — the current window's `top_spenders` call, then a SECOND call for exactly the group keys that call returned (originally another `top_spenders` call; revised post-audit to `dashboards.store.spend_for_groups`, see Fork 4 and §4) — joined by `group_key` in Python. It does **not** issue one query per group. | Directly informed by D-011's own security review (Finding #1: `forecast_all_budgets` doing up to 4 sequential queries per budget was flagged as resource-amplification risk even at a capped row count). This task designs the bound in from the start rather than fixing it after an audit: total queries per request is O(1) with respect to the number of groups, not O(groups). |
| **3 — bounded total baseline span, not just a bounded window** | `AnomalyQuery.baseline_periods` is capped `1 <= baseline_periods <= 90` (same shape as D-011's list caps), but the window itself already caps at 400 days (D-008's own `_MAX_WINDOW_DAYS`, reused unchanged). A naive combination (400-day window × 90 baseline periods) would ask the database to scan ~98 years of history in the baseline query alone. A dedicated `_bounded_baseline_span` validator additionally caps `window_duration * baseline_periods <= 400 days` (the same `_MAX_WINDOW_DAYS` constant, reused as the ceiling for the total span, not just the primary window). | This is the D-011-lesson applied proactively rather than reactively: the audit for that task caught a resource-amplification issue after the fact (Finding #1); this task's schema makes the equivalent class of issue structurally impossible before an audit even runs. `min_floor_cents`/`ratio_threshold` are library defaults (module constants), not query parameters — keeping the query surface itself, not just its cost, minimal. |
| **4 — reuse `dashboards.store` aggregates, one small addition (`spend_for_groups`) instead of new SQL in `delta.chargeback`** | Chargeback reuses D-008's `top_spenders` (ranked breakdown) and `spend_summary` (true, unbounded total — added post-audit, see §4) unchanged. Anomaly detection originally called `top_spenders` twice (current + baseline); the independent security review (Finding #1) caught that a group ranking in the CURRENT window's top-N could rank OUTSIDE a separately-ranked baseline window's own top-N, silently reading as zero prior spend. Fixed by adding `dashboards.store.spend_for_groups` — same shape as `top_spenders` (same table, same window/scope clauses) but filtered to a caller-supplied `group_keys` list instead of ranked+limited; the baseline call now asks for exactly the current window's own group keys. Still no new SQL written inside `delta.chargeback` itself — the one new primitive lives in `dashboards.store`, alongside `top_spenders`/`spend_summary`, and is itself covered by `tests/dashboards/test_store_db.py`. | D-008's existing aggregates are already tested, already RLS-safe, already capped. `spend_for_groups` is the minimal correct extension — not a second independent reimplementation of "sum cost per group," but the same query shape restricted by an explicit key set rather than a rank+limit, which is what "match THIS group's own baseline" actually requires. |
| **5 — share_pct uses ONE accounting basis throughout: the gross debit-direction sum, from `spend_summary` for the denominator** | Chargeback's `share_pct = group.cost_cents * 100 / total_cost_cents` computes the denominator from `spend_summary` (unbounded — revised post-audit, see §4 Finding #2) and the numerator from `top_spenders`' ranked rows — both the SAME gross debit-direction accounting basis, never mixed with `budget_engine.spend.scope_spend_cents`'s NET (debit-minus-credit) expense balance. | D-011's audit caught exactly this class of bug (Finding #2: `SPEND_CONCENTRATION` mixed a gross numerator against a net denominator, nominally able to exceed 100%). This task avoids the gross/net mixing proactively by never touching the net-expense query at all; the independent review for THIS task then caught a related but distinct defect — the denominator being silently truncated to the top-`_MAX_GROUPS` rows rather than the true total — fixed by sourcing it from the unbounded `spend_summary` instead of summing the capped `top_spenders` rows. |
| **6 — anomaly detection only evaluates groups present in the CURRENT window** | `detect_anomalies` iterates `current_by_group.items()` only. A group that spent heavily in the baseline window but spent nothing in the current window is never flagged (no `SPEND_DROP`/underspend signal exists in this version). | "Anomalous spend" in a FinOps chargeback context means cost overruns operators need to act on, not underspend (which is not a risk requiring action). Scoping to current-window groups keeps the signal set small and actionable rather than noisy. Named as a deferral in §3, not silently omitted. |
| **7 — explicit, versioned method tag** | The response always carries `method: "trailing_average_ratio_v1"` (a literal, not free text) — mirrors D-011's `method: "current_rate_projection_v1"` fork exactly. A future different method gets a NEW literal, never a silent redefinition of this one. | Same honesty-boundary discipline as D-011: nobody downstream mistakes "a fixed-multiple trailing-average comparison" for a validated statistical or ML anomaly-detection model. |
| **8 — chargeback/showback framing is explicitly NOT billing** | Both `ChargebackReportView` and every UI surface state the figures are the same client-side cost estimates the rest of Delta already produces — informational cost-attribution for internal accounting, never an authoritative bill or invoice line item. Delta has no billing/AR (accounts-receivable) system anywhere in this codebase. | Reuses ADR-0001's own honesty-boundary language (*"...are client-side cost estimates, never authoritative bills"*) and ADR-0008's (*"Not billing-grade..."*) verbatim-style — chargeback/showback is a well-established FinOps term for exactly this: informational department cost attribution, distinct from a real invoice. Naming this explicitly prevents a downstream reader from assuming Delta can generate a bill. |
| **9 — no persisted state, no migration** | Every report is computed live from `ledger_entries` (D-003) at request time via `top_spenders` — nothing is stored, cached, or historized. | Mirrors D-008's and D-011's own "zero new migration" decision (pure read aggregates). A chargeback/anomaly report is a point-in-time view; persisting historical anomaly flags (to later ask "did we act on this spike?") is real future work this ADR does not claim to deliver — see §3. |
| **10 — mounted on the existing admin app, not a new process** | `GET /v1/admin/chargeback/report`, `GET /v1/admin/chargeback/anomalies` on the same D-007 admin app, same `require_admin` break-glass bearer auth. | Same operators, same auth, same trust boundary — mirrors D-008/D-009/D-011's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No trained/validated statistical or ML anomaly-detection model.** The trailing-average
  ratio is deliberately simple, deterministic arithmetic — not a z-score/stddev method, not
  a seasonality-aware model, not anything requiring a training set or backtest. Same rationale
  as D-011 §3: no ecosystem precedent to build one against, and doing so unilaterally here
  would be exactly the kind of scope-widening-under-ambiguity this task's operating procedure
  is instructed to avoid.
- **No underspend / `SPEND_DROP` signal.** Only cost overruns are flagged (Fork 6). A group
  whose spend fell to zero is not currently surfaced as anomalous — real, plausible future
  work, but a genuinely different signal shape this task does not claim to deliver.
- **No anomaly history / acknowledgment workflow.** Nothing persists a flagged anomaly, and
  there is no "operator dismissed this" or "operator resolved this" state — every request
  recomputes from scratch. A future `anomaly_acknowledgments` feature (store + dismiss +
  audit-trail via D-009's hash chain) is real, valuable future work, named honestly here
  rather than half-built.
- **Chargeback/showback is not billing.** No invoice, no accounts-receivable record, no
  currency conversion, no proration across partial periods beyond what the caller's own
  `start`/`end` window already implies. Figures are the same client-side cost estimates the
  rest of Delta already produces (Fork 8).
- **Anomaly detection is meaningful only with a non-trivial baseline.** A group with a
  baseline average of exactly zero always reads as `NEW_SPENDER` rather than an infinite or
  undefined ratio — this is a real limitation of ratio-based comparison against zero, not a
  bug: there is genuinely no "prior rate" to compare against yet.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant spend/anomaly leak | Every query runs on the caller's tenant-scoped (RLS) `AsyncSession`, opened via `get_tenant_session(tenant_id)` from the query-string `tenant_id`, mirroring D-008/D-011 exactly — no downstream function accepts a session or tenant id independent of that RLS-confined session; the new `spend_for_groups` primitive (Fork 1a) is RLS-confined identically | `test_chargeback_report_cross_tenant_isolation`, `test_anomaly_report_cross_tenant_isolation`, `test_cross_tenant_report_is_isolated_over_http`, `test_spend_for_groups_cross_tenant_isolation` |
| Resource amplification via `baseline_periods` × window duration | `AnomalyQuery._bounded_baseline_span` rejects any combination where `window_duration * baseline_periods > 400 days`; `baseline_periods` itself is capped `1..90`; the current-window `top_spenders` call is capped at `_MAX_GROUPS = 100` rows, and the baseline `spend_for_groups` call is bounded by that same ≤100-element `group_keys` list (not a separate, independently-capped ranking) | `test_anomaly_query_bounded_total_baseline_span_rejected`, `test_anomaly_query_bounded_total_baseline_span_accepted_at_the_edge`, `test_anomalies_baseline_span_too_large_is_422` |
| N+1 query amplification per group | `get_anomaly_report` issues exactly 2 queries total (current-window `top_spenders` + baseline-window `spend_for_groups`), regardless of group count; `get_chargeback_report` issues exactly 2 queries (`spend_summary` for the true total + `top_spenders` for the ranked breakdown) — verified by code inspection, not just row caps | code review; no loop over groups issues a query |
| `share_pct` mixing gross/net accounting bases (D-011's Finding #2 class of bug) | Both numerator (`top_spenders`) and denominator (`spend_summary`) come from the SAME gross debit-direction accounting basis exclusively; `budget_engine.spend.scope_spend_cents` (net) is never imported into `delta.chargeback` | code review — `grep` confirms no `budget_engine.spend` import anywhere under `delta/chargeback/`; `test_chargeback_report_computes_share_pct` |
| `share_pct` denominator truncated to the top-`_MAX_GROUPS` rows, inflating displayed shares when >100 distinct groups exist (independent security review, Finding #2) | `total_cost_cents` now comes from `dashboards.store.spend_summary` (unbounded — no `_MAX_GROUPS` cap), not `sum()` over the `_MAX_GROUPS`-limited `top_spenders` rows; displayed `share_pct` values now honestly sum to <100% in aggregate when more groups exist than are shown, rather than silently summing to ~100% among a truncated top-N | `test_chargeback_report_computes_share_pct`; code review |
| Anomaly baseline computed from a SECOND, independently-ranked top-N query — misclassifies a current top-N spender with real prior spend as `NEW_SPENDER` if that prior spend doesn't independently rank in the baseline window's own top-N (independent security review, Finding #1) | Baseline totals now come from `dashboards.store.spend_for_groups`, queried for EXACTLY the `group_key`s the current-window `top_spenders` call returned — not a second, independent ranking of the baseline window | `test_spend_for_groups_returns_only_requested_keys`, `test_spend_for_groups_does_not_rank_or_limit`, `test_anomaly_report_detects_spend_spike` |
| `group_by` pinned as its own scope filter (nonsensical/self-referential query) | `_group_by_not_the_active_scope_filter` validator (reused verbatim pattern from D-008's `DashboardQuery`) rejects `group_by == "team_id"` when `team_id` is also pinned as a scope filter | `test_group_by_same_as_pinned_scope_rejected` |
| Naive-datetime window bounds silently misinterpreted as UTC | `require_aware_utc` validator (D-008's own, reused unchanged) rejects any `start`/`end` without an explicit timezone offset (any aware offset is accepted as an unambiguous instant — only a fully-naive value, with no offset at all, is rejected) | `test_naive_datetime_rejected` |
| `.days`-truncation window bypass (a known bug class caught in D-008's own security review) | Window-bound comparisons use exact `timedelta` arithmetic (`end - start > _MAX_WINDOW`), never `.days` (which silently truncates sub-day remainders and could let a >400-day-and-a-few-hours window slip through) | `test_window_exceeding_max_days_rejected`, `test_window_of_exactly_400_days_plus_hours_rejected` |
| Below-floor noise flagged as an anomaly | `min_floor_cents` (default $10) gates both `SPEND_SPIKE` and `NEW_SPENDER` — a group whose current spend never clears the floor is never evaluated, regardless of ratio | `test_below_floor_never_flagged_even_at_huge_ratio` |
| A flat/steady spender misflagged as anomalous | Ratio must clear `ratio_threshold` (default 3.0x) exactly — spend within normal fluctuation of its own baseline never crosses that bar | `test_flat_spend_is_not_flagged`, `test_spike_just_below_threshold_is_not_flagged` |
| `SQL`/query-string injection via `group_key`/tenant id | All values pass through parameterized SQLAlchemy queries (the same `top_spenders`/`spend_summary` D-008 already ships and tested, plus the new, identically-parameterized `spend_for_groups`); Pydantic's `extra="forbid"` on `_GroupedWindowQuery` rejects any unexpected field before it reaches the query layer | inherited from D-008's own audit (`docs/audit/d-008-security-audit.md`) — `delta.chargeback` calls unmodified or identically-parameterized functions |

## 5. Verification

- `black --check` / `ruff check .` clean.
- `tests/chargeback/` suite: 34 tests — 9 pure unit tests (`test_anomaly.py`, no DB/no I/O),
  11 pure schema-validation tests (`test_schemas.py`, no DB/no I/O), 7 DB-backed service tests
  (real ledger rows via the D-004 posting path, real RLS), 7 non-stubbed HTTP e2e tests (real
  ASGI app, real auth, real DB).
- `tests/dashboards/test_store_db.py` gained 5 tests covering the new `spend_for_groups`
  primitive (exact-key filtering, no ranking/limiting, empty-list short-circuit without
  issuing a query, cross-tenant isolation) — added post-audit alongside the Finding #1 fix.
- Full Delta suite green (567 passed, 15 skipped) — zero failures. The 15 skips are
  pre-existing, environment-gated conditions unrelated to this task (Orchestrator DB env vars
  not configured for the O-004 cross-product e2e tests, `helm` CLI not on PATH for the D-010
  chart tests). Modifications to existing code beyond the new `delta.chargeback` package: one
  router mount in `allocation_admin/app.py`, one new function (`spend_for_groups`) added to
  `dashboards/store.py` (existing `top_spenders`/`spend_summary` untouched), and a
  docstring-only clarification to `money.require_aware_utc` (no behavior change — see §4).
- Frontend: `npm run typecheck` clean, `npm run lint` clean (0 warnings/errors), `npm run build`
  succeeds (`/chargeback` registered as a dynamic route). Live browser smoke test performed
  against a real running backend with real seeded usage data (via the D-004 posting path, not
  hand-inserted rows): a spiking team (7 days @ $10/day baseline, $80 current) correctly shows
  `SPEND_SPIKE` at an 8.0x ratio with the "warn"-colored badge; a steady team (flat $15/day
  including the current day) correctly shows no anomaly row. Chargeback report table correctly
  computed `share_pct` (84.2% / 15.8%) and total spend ($95.00) across both teams.

## 6. Alternatives considered

- **Z-score / standard-deviation-based anomaly detection.** Rejected (Fork 1): with the small
  per-period sample sizes typical of a department's daily spend (a handful of buckets), variance
  estimates are unstable — a single noisy day can inflate the standard deviation enough to mask
  a real spike, or deflate it enough to flag ordinary fluctuation. A ratio against a trailing
  average needs no variance estimate at all and is far more robust at low sample counts.
- **A trained/validated ML anomaly-detection model.** Rejected for the same reason D-011
  rejected building a real forecasting model unilaterally: no prior ecosystem implementation to
  build from or review against, no training-data/backtest story, and doing so under an
  unattended, single-PR run without a dedicated modeling review cycle would be exactly the kind
  of scope-widening this run's procedure is instructed to avoid.
- **Real billing/invoicing instead of showback.** Rejected (Fork 8): Delta has no
  accounts-receivable system, no currency-conversion story, and no proration engine anywhere in
  this codebase. Framing the chargeback report as informational cost-attribution — honest about
  what it is — is the correct scope for this task; building real billing is a separate, much
  larger feature this ADR does not claim to deliver.
- **Per-group anomaly queries (one `top_spenders` call per group).** Rejected (Fork 2): would
  reintroduce the exact N+1 resource-amplification shape D-011's audit flagged for a different
  endpoint. Two bulk queries joined in Python is strictly cheaper and simpler.
