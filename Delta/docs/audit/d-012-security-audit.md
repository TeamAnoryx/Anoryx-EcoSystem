# D-012 Security Audit — Chargeback/Showback + Trailing-Average Anomaly Detection

- **Date:** 2026-07-08
- **Scope:** `Delta/src/delta/chargeback/` (the entire new package), the one new router mount
  in `Delta/src/delta/allocation_admin/app.py`, `Delta/tests/chargeback/`, and
  `Delta/docs/adr/0012-delta-chargeback-anomaly-detection.md` (the design record,
  cross-checked against the actual shipped code).
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per
  banked process rule #3 — re-run against the code, not implementer-self-verified).
- **Verdict:** **CLEAN** — no High or Critical findings. Four Low findings; all four
  addressed on this branch before merge.

## Note on tooling

Semgrep's registry could not be fetched in the audit environment (the egress proxy denies
`CONNECT` to `semgrep.dev` — the same known limitation recorded in every prior audit this
session; see `docs/audit/d-011-security-audit.md`). This pass is manual dataflow analysis,
tracing every claim in the ADR back to the actual source, per the same accepted precedent.
`delta-ci.yml`'s `quality` job's Semgrep step runs for real in CI (registry reachable there)
and remains the authority of record for SAST on this PR.

## What was actively tried and found sound

- **Cross-tenant leakage.** Every query in `service.py` runs on the caller's RLS-confined
  `AsyncSession`, opened via `get_tenant_session(tenant_id)` from the query-string
  `tenant_id`; no downstream function accepts a session or tenant id independent of that
  session. Verified by `test_chargeback_report_cross_tenant_isolation`,
  `test_anomaly_report_cross_tenant_isolation`, `test_cross_tenant_report_is_isolated_over_http`.
- **Resource amplification.** `AnomalyQuery._bounded_baseline_span` rejects any
  `window_duration * baseline_periods > 400 days`; `baseline_periods` is field-validated to
  `1..90` before that model validator runs (so a negative/absurd value can't bypass the span
  check); `end > start` is enforced so a negative duration can't be used to defeat the
  multiplication either. Both `top_spenders` calls (and the replacement `spend_for_groups`
  call, see Finding #1 below) stay bounded at or under `_MAX_GROUPS = 100`.
- **Auth.** `require_admin` is a router-level dependency (`router.py:26`,
  `dependencies=[Depends(require_admin)]`), covering both `GET /report` and `GET /anomalies`
  — not attached per-route, so neither endpoint could accidentally be left unguarded.
  Confirmed by `test_report_missing_bearer_is_401`, `test_anomalies_missing_bearer_is_401`.
- **Division-by-zero / degenerate math.** `anomaly.py` requires `baseline_periods >= 1`
  (raises `ValueError` otherwise, and the schema layer additionally enforces `1..90` before
  the service ever calls it); a zero baseline average routes to `NEW_SPENDER` rather than
  dividing by zero.
- **Money discipline.** `grep` across `delta/chargeback/` found zero uses of `float(` and no
  monetary field typed as anything but `int`; only `share_pct`, `ratio`, and
  `baseline_avg_cents`'s float form are `float` — all three are response-only, informational
  fields, never read back into any budget/enforcement decision (there is no enforcement
  decision anywhere in this package — every endpoint is a read-only report).
- **No `session.begin()` wrapping.** `grep` confirmed no call in `delta/chargeback/` wraps
  `get_tenant_session` in `session.begin()` — the known Delta footgun.
- **No raw SQL / accounting-basis mixing.** No `text()`/raw SQL anywhere in the package; no
  import of `budget_engine.spend` (the NET accounting-basis query) anywhere under
  `delta/chargeback/` — confirmed by `grep`.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | Low | `chargeback/service.py` (`get_anomaly_report`, pre-fix line 76) | The baseline window's group totals were fetched via a SECOND, independently-ranked `top_spenders` call (`limit=_MAX_GROUPS`), then joined to the current window's groups by `group_key` with a `.get(group_key, 0)` fallback. A group present in the CURRENT window's top-100 whose (genuine, non-zero) baseline-window spend does not independently rank in the baseline window's OWN top-100 (realistic for high-cardinality dimensions like `agent_id`, or a group that only recently became a top spender) read as baseline = 0 and was misclassified as `NEW_SPENDER` (severity `info`) instead of `SPEND_SPIKE` (severity `warning`) — or missed entirely if the ratio math happened to fall under the floor. Not an attacker-driven exploit — a detection-accuracy defect: a real cost overrun could be downgraded/mislabeled, causing an operator to deprioritize it. No cross-tenant or data-leak impact either way. | **Fixed.** Added `dashboards.store.spend_for_groups(session, *, start, end, group_by, group_keys, scope)` — same query shape as `top_spenders` (same table, window, and scope clauses) but filtered to a caller-supplied `group_keys` list via `WHERE group_col.in_(...)` instead of ranked + `LIMIT`. `get_anomaly_report` now fetches baseline totals for EXACTLY the group keys the current-window `top_spenders` call returned, so a group's own baseline is always matched correctly regardless of how it separately ranks in the baseline window. Still exactly 2 queries total (Fork 2 preserved). New tests: `test_spend_for_groups_returns_only_requested_keys`, `test_spend_for_groups_does_not_rank_or_limit`, `test_spend_for_groups_empty_keys_returns_empty_without_querying`, `test_spend_for_groups_cross_tenant_isolation` (`tests/dashboards/test_store_db.py`). ADR-0012 Forks 2/4 and §4 updated. |
| 2 | Low | `chargeback/service.py` (`get_chargeback_report`, pre-fix line 49) | `total_cost_cents` was computed as `sum(r.cost_cents for r in rows)` over only the top-`_MAX_GROUPS` (100) rows `top_spenders` returned. For a tenant with more than 100 distinct groups in the window, the denominator silently excluded the tail, so every displayed `share_pct` overstated that department's true share of total spend — while the displayed shares still summed to ~100% among themselves, masking the truncation rather than revealing it. The ADR's own framing ("a chargeback/showback report wants every department, not just a top-N ranking") was contradicted by the 100-cap denominator. Not a security vulnerability — an accounting-accuracy defect in a report explicitly meant to inform real department cost decisions. | **Fixed.** `get_chargeback_report` now calls `dashboards.store.spend_summary` (D-008's existing, unbounded total-spend aggregate — no new query logic) for `total_cost_cents`, and `top_spenders` (unchanged, capped at 100) only for the ranked row breakdown. `share_pct` is now a fraction of the TRUE total; when more than 100 groups exist, the displayed rows' shares now honestly sum to less than 100% in aggregate rather than falsely appearing complete. Existing test `test_chargeback_report_computes_share_pct` still passes unchanged (single-digit group counts, where the fix is a no-op numerically). ADR-0012 Fork 5 and §4 updated. |
| 3 | Low | `docs/adr/0012-delta-chargeback-anomaly-detection.md` §4 (pre-fix) | Several test names cited in the "Verified by" column drifted from the actual function names in `tests/chargeback/` (e.g. `test_chargeback_cross_tenant_isolation` vs. the real `test_chargeback_report_cross_tenant_isolation`; `test_bounded_total_baseline_span_rejected` vs. the real `test_anomaly_query_bounded_total_baseline_span_rejected`). All claimed behavior was in fact covered — the identifiers just didn't match, so a reader grepping for the literal name wouldn't find the proof. No runtime impact. | **Fixed.** §4's "Verified by" column now cites the exact, correct test function names for every row, re-checked against `grep` output of the real test files. |
| 4 | Low | `src/delta/money.py:69` (`require_aware_utc`, pre-fix) | The docstring/error message said "Require a timezone-aware datetime (the wire is RFC 3339 UTC)," but the actual check (`value.tzinfo is None or value.tzinfo.utcoffset(value) is None`) only rejects a fully NAIVE datetime — it accepts ANY aware offset, not specifically a zero/UTC offset. No security or correctness impact: an aware-offset datetime is an unambiguous instant regardless of the offset it carries, and all downstream window/timedelta math is offset-correct either way — the dangerous case (a naive datetime silently assumed to be UTC) is correctly rejected. This was a naming/documentation mismatch, not a validation bypass. Pre-existing, shared code (used by D-008/D-011 as well as this task) — out of D-012's own scope to change behaviorally. | **Fixed (docstring only, no behavior change).** Clarified the docstring to state precisely what is and isn't enforced: rejects naive values, accepts any aware offset, does not additionally require the offset to be zero/UTC. No test changes required (existing `require_aware_utc` tests already only assert on naive-vs-aware, not on offset value, so behavior-preserving by construction). |

## Threat model cross-reference

See `docs/adr/0012-delta-chargeback-anomaly-detection.md` §4 for the full vectors-to-
mitigations-to-tests table this audit validated against and then updated post-fix (cross-tenant
isolation, resource amplification via baseline span, N+1 query amplification, gross/net
accounting-basis mixing, the two truncation defects above, `group_by`/scope self-reference,
naive-datetime rejection, `.days`-truncation window bypass, below-floor noise suppression,
flat-spend false positives, and SQL-injection surface).

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-012 chargeback/anomaly surface listed under Scope above, plus the
one new `dashboards.store.spend_for_groups` primitive added during the fix pass (itself a
narrow, RLS-identical extension of the already-audited `top_spenders`/`spend_summary`
functions — not a re-audit of `dashboards.store` as a whole, which remains covered by
`docs/audit/d-008-security-audit.md`). It does not re-audit `budget_engine.spend`/`decision`
(unchanged, already audited at `docs/audit/d-005-security-audit.md`) — D-012 never imports it.
Per ADR-0012 §3, "trailing-average ratio" is deliberately simple, deterministic arithmetic, not
a trained or validated statistical/ML anomaly-detection model — this review assessed it as
such, not against any accuracy/detection-quality bar a real anomaly-detection model would need
to clear. The two truncation findings (#1, #2) are detection-accuracy and accounting-accuracy
limitations of the `_MAX_GROUPS = 100` cap under high-cardinality group dimensions, not security
vulnerabilities — both are now fixed, but a tenant with more than 100 distinct groups in a
single window will still only see the top 100 ranked in the chargeback report's row list (the
report's `total_cost_cents` is now correct regardless; only the row LIST itself is still capped,
by design, mirroring D-008's own `top_spenders` cap).
