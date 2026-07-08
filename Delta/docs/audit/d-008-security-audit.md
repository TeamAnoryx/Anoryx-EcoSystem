# D-008 Security Audit — Delta Live Cost-to-Value Dashboards

- **Date:** 2026-07-07
- **Scope:** `Delta/src/delta/dashboards/` (store, schemas, service, router), the modified
  `Delta/src/delta/allocation_admin/app.py` (mounts the dashboards router), `Delta/tests/
  dashboards/`, and the D-008 additions to `Delta/frontend/` (`src/app/(admin)/dashboards/`,
  `src/components/dashboards/`, and the dashboards-specific additions to `src/lib/admin-client.ts`
  / `src/lib/types.ts` / `src/lib/bff.ts`).
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per banked
  process rule #3 — re-run against the code, not implementer-self-verified).
- **Verdict:** **CLEAN** — no High or Critical findings. Four Low findings; three fixed on this
  branch before merge, one is a tooling gap (see below).

## Note on tooling

Semgrep's registry rulesets (`p/python`, `p/security-audit`, `p/secrets`) could not be fetched in
the audit environment (the egress proxy returns 403 on `CONNECT` to `semgrep.dev`, and no offline
rule cache exists). This pass is therefore **manual dataflow analysis only** for the two SQL-
construction surfaces the review specifically targeted (`getattr(ledger_entries.c, group_by)` and
`func.date_trunc(bucket, ...)`), plus tenant-isolation and frontend-injection review. The
`delta-ci.yml` `quality` job's `semgrep scan --config=p/python --severity=ERROR` step runs for
real in CI, where the registry is reachable, and is the authority of record for SAST on this PR
(banked rule #4 — CI is authoritative, not a local proxy-limited approximation). Recorded as
finding #4 below so the gap is visible, not silently absent from the record.

## What was actively tried and found sound

- **SQL construction — `group_by` reaching `getattr`** — `group_by` is constrained by a Pydantic
  `Literal["team_id","project_id","agent_id"]` in `TopSpendersQuery`, enforced before
  `store.top_spenders` is ever called; `getattr(ledger_entries.c, group_by)` resolves to a real
  SQLAlchemy `Column` object, never a string interpolated into SQL text. No attacker-controlled
  string reaches the query builder unvalidated.
- **SQL construction — `bucket` reaching `date_trunc`** — same `Literal["hour","day"]` constraint;
  `func.date_trunc(bucket, ...)` binds `bucket` as a query parameter through SQLAlchemy/asyncpg,
  never string-interpolated. No SQL injection path.
- **Tenant isolation** — every route opens `get_tenant_session(tenant_id)` (the `delta_app`
  NOBYPASSRLS role, transaction-local `app.current_tenant_id` GUC); RLS confines every
  `ledger_entries` row to the caller's tenant regardless of the optional team/project/agent scope
  filters. Verified end to end by `test_cross_tenant_spend_is_isolated` and
  `test_cross_tenant_summary_is_isolated_over_http`.
- **No `session.begin()` double-wrap** — the module is read-only; every query runs directly on the
  session's autobegun transaction (the F-007/F-009/F-018 bug class does not apply here since
  nothing is written).
- **Money/precision** — `SUM(BIGINT)` over Postgres promotes to `numeric`, read back as Python
  arbitrary-precision `int` in `store.py` (`int(row[0])`) — no overflow at any value
  `MAX_BUDGET_COST_CENTS` (1e11) permits per row. `cost_per_request_cents` and
  `burn_rate_cents_per_hour` are derived floats (ratios), never persisted or treated as a
  monetary amount in their own right; the frontend renders them through `money.ts`'s existing
  client-side-cost-estimate framing, consistent with the rest of Delta.
- **Frontend injection** — no `dangerouslySetInnerHTML` or raw `innerHTML` anywhere in the D-008
  components; `group_key` (an operator-supplied-at-ingest team/project/agent id) and all currency/
  count values flow through ordinary JSX text/attribute interpolation, which React escapes
  automatically. The BFF `ALLOWED_ROOTS` addition (`"dashboards"`) is the only change to
  `bff.ts`; the fail-closed unauthenticated-session check and the path-traversal guard
  (rejecting `..`, `.`, embedded `/`/`\`) are unchanged and still apply to every segment. No new
  `process.env` read outside `env.ts`.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | Low | `dashboards/store.py` `spend_time_series` | No row-count cap independent of the window-days check — at `bucket='hour'` and the maximum ~400-day window, a single call could return ~9,600 rows. Bounded (not unbounded), and reachable only by the trusted single admin bearer, but a real resource-amplification vector for an already-authenticated caller. | **Fixed.** Added `_MAX_TIMESERIES_POINTS = 2000` and `.limit(...)` on the query, mirroring D-007's list-response cap pattern (`test_time_series_row_count_is_capped`, which lowers the cap via `monkeypatch` and proves it's enforced without seeding thousands of real rows). |
| 2 | Low | `dashboards/schemas.py` `DashboardQuery._validate_window` | The window cap compared `(end - start).days > _MAX_WINDOW_DAYS`; `timedelta.days` truncates, so a window of 400 days + up to 23h59m has `.days == 400` and would incorrectly pass — an ~0.3% overshoot of the intended bound. | **Fixed.** Compares the exact `timedelta` against `timedelta(days=400)` instead of the truncated `.days` integer (`test_window_of_exactly_400_days_plus_hours_rejected`, `test_window_of_exactly_400_days_accepted`). |
| 3 | Low | `frontend/.../dashboards/page.tsx` `resolveGroupBy` | Cast `searchParams.group_by` to `DashboardGroupDimension` without checking it was actually one of the three valid values before use — a hand-crafted `?group_by=bogus` URL would pass an unvalidated string through to `adminApi.getTopSpenders`. Not an injection (the backend's `Literal` constraint still rejects it with 422, which the page already catches into a friendly error), but the validation belonged at the point of use, not two layers downstream. | **Fixed.** `resolveGroupBy` now checks membership against `VALID_GROUP_DIMENSIONS` before treating the query param as a valid dimension, falling back to the first unpinned dimension exactly as it already did for a missing/pinned value. Covered structurally by the existing backend 422 test (`test_top_spenders_group_by_pinned_scope_is_422`); a dedicated frontend unit test was not added (no other page-level component in this console has one — `page.tsx` server components aren't part of the existing unit/render test surface — so this stays proportionate to established precedent rather than introducing a new test shape for one guard clause). |
| 4 | Low | tooling | Mandated Semgrep pass could not execute in the audit environment (proxy denies `semgrep.dev`, no offline cache). Manual analysis only for this pass. | **Not a code fix** — recorded so the gap is visible. `delta-ci.yml`'s `quality` job runs the real Semgrep scan in CI, which has network access to the registry; that CI run is the authority of record for SAST on this PR (same accepted pattern as `docs/audit/d-007-security-audit.md`'s identical tooling note). |

## Threat model cross-reference

See `docs/adr/0008-delta-cost-dashboards.md` §5 for the full vectors-to-tests table this audit
validated against (cross-tenant isolation, double-counting, unbounded window, group-by/scope
conflict, malformed window, missing/wrong bearer, `getattr`/`date_trunc` construction safety).

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-008 surface listed under Scope above. It does not re-audit the
unchanged D-003 `ledger_entries`/RLS primitive itself (already audited at
`docs/audit/d-003-security-audit.md`), the unchanged D-007 `require_admin`/BFF-only frontend
pattern this task extends (already audited at `docs/audit/d-007-security-audit.md`), or the
unchanged D-004 posting path this task's aggregates read from (already audited at
`docs/audit/d-004-security-audit.md`).
