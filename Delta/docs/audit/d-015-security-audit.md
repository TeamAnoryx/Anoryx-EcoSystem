# D-015 Security Audit — Project Management: Sprints, Tasks, Dependency Mapping

- **Date:** 2026-07-09
- **Scope:** `Delta/src/delta/pm/` (the entire new package), `Delta/src/delta/persistence/
  migrations/versions/0009_pm_sprints_dependencies.py` (new tables, RLS, grants, CHECK
  constraints), the additive-only changes to `Delta/src/delta/identifiers.py` and
  `Delta/src/delta/persistence/models.py`, the one new router mount in
  `Delta/src/delta/allocation_admin/app.py`, `Delta/tests/pm/`, the new frontend surface
  (`Delta/frontend/src/app/(admin)/pm/`, `Delta/frontend/src/components/pm/`, and the
  additive changes to `types.ts`/`admin-client.ts`/`bff.ts`/`app-nav.tsx`), and
  `Delta/docs/adr/0015-delta-pm-sprints-dependencies.md` (the design record, cross-checked
  against the actual shipped code).
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per
  banked process rule #3 — re-run against the code, not implementer-self-verified). The
  reviewer wrote and ran adversarial reproduction scripts against a live local Postgres
  rather than relying on code review alone.
- **Verdict:** initial pass **BLOCK** — two Medium findings, both concrete and reproduced
  (not theoretical). Both **fixed on this branch before merge**; re-verified below.

## What was actively tried and found sound

- **Cross-tenant isolation.** Every function in `pm/store.py` runs on the caller's
  tenant-scoped (RLS, `NOBYPASSRLS`) `AsyncSession` via `get_tenant_session` — no raw SQL,
  no privileged-session path anywhere in `delta.pm`.
- **Cross-tenant FK reference.** `task_dependencies`'s composite FKs
  (`blocking_task_id, tenant_id`) / (`blocked_task_id, tenant_id`) against `tasks`'s
  `uq_task_id_tenant` make a cross-tenant dependency edge structurally impossible,
  independent of RLS.
- **`completed_at`/`status` consistency.** Guarded by both `update_task_status` (sets
  `completed_at = now` iff the new status is `"done"`, unconditionally) and the DB
  `CHECK ((status = 'done') = (completed_at IS NOT NULL))` — no code path drives the two
  out of sync.
- **`story_points` float coercion.** `mode="before"` + `reject_non_integer` rejects a wire
  float (including `NaN`/`Infinity`), bool, and numeric string outright, before Pydantic's
  own lax int coercion ever runs.
- **Velocity/bottleneck report amplification.** Both are single bounded SQL aggregate
  queries (`GROUP BY`/`HAVING`/`ORDER BY` inside Postgres) — no per-row Python loop, no
  N+1.
- **Auth.** `require_admin` (D-007's unmodified break-glass bearer) is a router-level
  `dependencies=[Depends(require_admin)]` covering all 9 PM routes — no per-route opt-out.
- **Frontend token isolation.** `admin-client.ts` remains `server-only`; every new PM
  client component calls a `"use server"` Server Action in `pm/actions.ts`, never
  `admin-client.ts` directly. Adding `"pm"` to `bff.ts`'s `ALLOWED_ROOTS` reuses the
  existing traversal guard unmodified — no new SSRF surface. `pm/actions.ts` maps
  `AdminApiError` the same way `erp/actions.ts` does — the upstream `detail` field is
  surfaced, never a raw internal stack/trace.
- **Validation.** `extra="forbid"` everywhere; every free-text field rejects control
  characters; `require_aware_utc` on `start_date`/`end_date`; Literal-typed
  sprint/task status reject unknown values; self-dependency and missing-sprint/
  missing-task both correctly 404/422.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | Medium | `pm/service.py::create_dependency` (edge-check-then-insert, pre-fix) | Dependency-cycle prevention was a pure app-layer check-then-insert with no database backstop for acyclicity. The migration's `UniqueConstraint(blocking_task_id, blocked_task_id)` only blocks a literal duplicate edge, not a cycle. Under default `READ COMMITTED` isolation, two concurrent `create_dependency` calls (e.g. one `A→B`, one `B→A`, both cycle-free against the graph each individually observed) each pass the BFS and both commit — jointly closing a 2-node cycle the ADR's threat model claimed was impossible. **Reproduced**: 14/15 `asyncio.gather` trials against the live DB persisted a closed 2-node cycle, both requests returning `201`. | **Fixed.** `create_dependency` now takes `SELECT pg_advisory_xact_lock(hashtext(:tenant_id))` (the same tenant-serializing lock shape D-009's `append_history` already uses) before loading the edge set, so concurrent dependency-graph mutations for one tenant are ordered — the second caller in any race observes the first's committed edge and is correctly rejected as a cycle. Regression test: `test_create_dependency_race_is_serialized_by_advisory_lock` (asserts exactly one of two concurrent opposite-direction edge creates succeeds, the other raises `DependencyCycleError`, and no closed cycle survives in the graph) — stable across 5 repeated runs. |
| 2 | Medium | `pm/store.py::list_all_dependency_edges` (pre-fix, routed through `_clamp_limit`) | The function's `limit` parameter (default `_MAX_DEPENDENCY_EDGES_CONSIDERED = 2000`) was silently routed through `_clamp_limit`, whose ceiling is `MAX_LIST_LIMIT = 500` — an unrelated pagination bound. The cycle-freedom BFS was therefore fed at most 500 arbitrarily-ordered rows (no `ORDER BY`), not the 2000 the code constant and ADR §4 both promised, and edges past the cap were silently dropped rather than failing closed. **Reproduced**: a 600-edge chain in one tenant, closing edge `t600→t0`, was accepted (a cycle was created) because the BFS never saw more than 500 of the 600 edges. | **Fixed.** `list_all_dependency_edges` no longer routes through `_clamp_limit`/`MAX_LIST_LIMIT`; it now fetches `limit + 1` rows (deterministically ordered by `created_at, dependency_id`) so the caller can detect truncation. `create_dependency` fails closed: if the fetched edge count exceeds `MAX_DEPENDENCY_EDGES_CONSIDERED`, it raises a new `TooManyDependencyEdgesError` (mapped to `422 too_many_dependency_edges`) instead of running the BFS against a possibly-incomplete graph. Regression tests: `test_create_dependency_fails_closed_when_edge_bound_reached` (service-level, bound lowered via `monkeypatch` to keep the test fast) and `test_list_all_dependency_edges_reports_truncation_not_silently_clamped` (store-level, asserts `limit + 1` rows are returned when more edges exist, proving no silent clamp). |

## Threat model cross-reference

See `docs/adr/0015-delta-pm-sprints-dependencies.md` §4 for the full vectors-to-mitigations-to-tests
table. The "a dependency edge closes a cycle in the task graph" row is updated by this audit:
the mitigation is now the bounded BFS **plus** the tenant-serializing advisory lock **plus**
the fail-closed truncation guard — the original ADR draft named only the BFS, which this audit
found insufficient on its own (findings #1 and #2 above).

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-015 PM surface listed under Scope above. It does not re-audit
`allocation_admin.auth.require_admin`, `delta.persistence.database.get_tenant_session`, or
`delta.persistence.audit_log.append_history` (all unchanged, already audited across D-007/
D-009's own audit records) — D-015 calls the first two unmodified (and deliberately does NOT
call the third — task/sprint edits are business-process data, not financial transactions,
per ADR-0015 Fork 6) and this review confirmed it does so correctly. Per ADR-0015 §1/§3, this
is a deliberately bounded vertical slice of the roadmap's "sprint-velocity tracking,
dependency mapping, execution-bottleneck prediction — real-time" — this review assessed the
code as the bounded slice it claims to be (sprints, tasks, a real dependency graph, a
deterministic bottleneck heuristic), not against real-time push infrastructure or
external-issue-tracker-integration security this task explicitly declines to build.
