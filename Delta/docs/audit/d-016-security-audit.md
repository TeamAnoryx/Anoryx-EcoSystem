# D-016 Security Audit — Team Capacity Management: Teams, Task Assignment, Utilization, Advisory Rebalancing

- **Date:** 2026-07-09
- **Scope:** `Delta/src/delta/capacity/` (the entire new package), `Delta/src/delta/persistence/
  migrations/versions/0010_team_capacity.py` (new `teams` table, RLS, grants, CHECK constraints,
  plus the additive nullable `team_id` column on D-015's existing `tasks` table), the
  additive-only changes to `Delta/src/delta/identifiers.py` (comment only) and
  `Delta/src/delta/persistence/models.py`, the one new router mount in
  `Delta/src/delta/allocation_admin/app.py`, `Delta/tests/capacity/`, the new frontend surface
  (`Delta/frontend/src/app/(admin)/capacity/`, `Delta/frontend/src/components/capacity/`, and
  the additive changes to `types.ts`/`admin-client.ts`/`bff.ts`/`app-nav.tsx`), and
  `Delta/docs/adr/0016-delta-team-capacity-management.md` (the design record, cross-checked
  against the actual shipped code).
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per
  banked process rule #3 — re-run against the code, not implementer-self-verified). The
  reviewer wrote and ran adversarial reproduction scripts against a live local Postgres
  (a genuinely concurrent race test, a cross-tenant isolation script bypassing the service
  layer to hit `store.py` directly) rather than relying on code review alone, and explicitly
  re-checked whether either of D-015's two audit-confirmed bug classes (a TOCTOU race with no
  DB backstop; a query helper silently routed through the wrong, smaller limit constant)
  recur in this feature.
- **Verdict:** **CLEAN** — no High, Critical, Medium, or Low findings.

## D-015 bug-class recheck (explicitly re-verified, not assumed absent)

- **TOCTOU race.** Disproven by reproduction: unlike D-015's cycle check (a cross-row graph
  invariant enforced only in application code, genuinely racy), this feature has no
  check-then-write path guarding a cross-row invariant. `create_team` is an unconditional
  INSERT; `update_team_capacity` and `assign_task_team` are single unconditional UPDATEs —
  there is no "read state, decide, write" gate for a concurrent request to race past. The
  existence checks in `service.assign_task_team` (does the task exist? does the team exist?)
  are backed by DB-level guarantees (the composite `fk_task_team` FK, RLS, the primary key) —
  no DELETE grant exists on `teams` or `tasks`, so neither can vanish mid-transaction. A
  10-way `asyncio.gather` race against `assign_task_team` on one task produced 10 clean
  successes and a consistent final state (last-write-wins is the correct, intended semantic
  for "which team is this task currently assigned to" — there is no invariant a race could
  violate).
- **Wrong-limit-constant truncation.** Disproven by code trace: `list_tasks_for_capacity` and
  `list_teams` both correctly route through this package's OWN `_clamp_limit`/
  `MAX_LIST_LIMIT = 500` (mirrors D-015's post-fix `list_all_dependency_edges` shape exactly).
  `list_movable_tasks` deliberately uses its own larger, purpose-specific bound
  (`_MAX_MOVABLE_TASKS_CONSIDERED = 1000`, not router-exposed) — the opposite failure mode
  from D-015's bug (a too-large bound feeding a heuristic, not an accidentally-shrunk one).
  No helper in `delta.capacity.store` is routed through a constant that belongs to an
  unrelated, smaller-scoped concern.

## What was actively tried and found sound

- **Cross-tenant isolation (live-reproduced with an adversarial script, not just RLS-by-
  inspection).** Tenant B reading tenant A's task via `get_task_for_capacity` returns `None`.
  B attempting to assign A's task raises `TaskNotFoundError` (404). A attempting to assign its
  own task to B's `team_id` raises `TeamNotFoundError` (404), because `get_team` is itself
  RLS-scoped. A raw `store.assign_task_team` call bypassing the service-layer check entirely
  (A's task, B's team_id) was rejected at the DATABASE layer with a `ForeignKeyViolationError`
  from `fk_task_team` — the composite `(team_id, tenant_id)` FK is a structural backstop
  independent of the app-layer check, and the task's assignment was left unchanged. Cross-
  tenant task-team assignment is genuinely impossible, not just app-layer-guarded.
- **Float/type coercion on `capacity_points_per_sprint`.** `reject_non_integer` at
  `mode="before"` correctly rejects a float with no fractional part (`5.0`), a fractional
  float (`5.5`), a numeric string (`"5"`), a bool (`True`), negative zero, `NaN`, and
  `Infinity` (including the JSON-level `1e400` overflow-to-infinity form) — before Pydantic's
  own lax coercion ever runs. `Field(ge=0, le=MAX_CAPACITY_POINTS)` independently rejects
  out-of-range integers.
- **Divide-by-zero / utilization-ratio branch, independently re-derived.** `(capacity=0,
  remaining=0) → 0.0`; `(capacity=0, remaining=5) → None`; `(capacity=5, remaining=8) → 1.6`;
  `(capacity=3, remaining=0) → 0.0` — matches ADR-0016 Fork 5 exactly for every input
  combination tried; no path raises, returns `inf`, or returns `NaN`.
- **The rebalance report's "read-only" claim.** Every function reachable from
  `get_rebalance_report` (`store.get_utilization_rows`, `store.list_movable_tasks`,
  `service._greedy_rebalance`) is either a SELECT or a pure in-memory computation — a full
  grep of `capacity/store.py` confirms the only `insert`/`update` statements in the entire
  module are `create_team`, `update_team_capacity`, and `assign_task_team`, none of which sit
  on the rebalance-report call path. Generating a suggestion cannot mutate anything.
- **Auth.** All 7 capacity routes live under the single router-level
  `dependencies=[Depends(require_admin)]` (mirrors D-007's unmodified break-glass bearer) — no
  route is defined outside that router, no privileged/`BYPASSRLS` session appears anywhere in
  `delta.capacity` (every route uses `get_tenant_session`).
- **Resource amplification.** Utilization is one bounded aggregate query plus a pure
  in-memory loop over its (small) result; rebalance is two bounded queries plus a pure
  function — no N+1 anywhere in either report.
- **Frontend token isolation.** `admin-client.ts` remains `server-only`; every mutation flows
  through a `"use server"` action in `capacity/actions.ts`, which surfaces only the mapped
  `.detail` string, never a raw upstream stack/trace. Adding `"capacity"` to `bff.ts`'s
  `ALLOWED_ROOTS` inherits the existing traversal guard unmodified — no new SSRF surface.
  `TaskTeamAssignSelect`/`ApplyRebalanceSuggestionButton` only ever pass server-supplied team
  ids into a mutation, which are independently re-validated as UUIDs at the API boundary
  regardless of what the client sends.
- **Validation.** `extra="forbid"` everywhere; `name` rejects control characters; missing-team
  and missing-task both correctly 404 with a distinguishable `detail` (`team_not_found` vs
  `task_not_found`); every query in `delta.capacity.store` is a parameterized SQLAlchemy Core
  statement — no raw string-interpolated SQL anywhere.

## Non-defect design notes (recorded, not findings)

Two observations surfaced during the review that are explicitly NOT security findings — both
sit entirely within the trusted, admin-authenticated break-glass plane and are self-inflicted
at worst (an operator's own data), not exploitable by another party:

- The rebalance suggestion considers at most 1000 movable tasks per sprint
  (`_MAX_MOVABLE_TASKS_CONSIDERED`) — a real, if generous, bound named in the code, not a
  silent gap.
- `get_utilization_rows` returns one row per team with no separate team-count cap on that
  specific query (bounded only by however many teams the tenant has created via the already-
  `_clamp_limit`-bounded `create_team`/`list_teams` path) — not a resource-amplification risk
  in practice, since team counts are operator-created and small.

## Threat model cross-reference

See `docs/adr/0016-delta-team-capacity-management.md` §4 for the full vectors-to-mitigations-
to-tests table this audit validated against (cross-tenant isolation, cross-tenant FK
enforcement, capacity float-coercion rejection, utilization resource amplification, the
divide-by-zero/undefined-ratio branch, the rebalance report's read-only guarantee, input
validation, and auth coverage).

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-016 capacity surface listed under Scope above. It does not
re-audit `allocation_admin.auth.require_admin` or `delta.persistence.database.get_tenant_session`
(both unchanged, already audited across D-007/D-009's own audit records) — D-016 calls both
unmodified and this review confirmed it does so correctly. It also does not re-audit
`delta.pm`'s own source files, which this task does not touch at all (ADR-0016 Fork 3) — only
the shared `tasks` table definition gains one additive column, reviewed here as part of
migration 0010. Per ADR-0016 §1/§3, this is a deliberately bounded vertical slice of the
roadmap's "squad performance, capacity tracking, automated resource allocation, real-time
utilization to prevent burnout" — this review assessed the code as the bounded slice it
claims to be (team-level capacity, advisory-only rebalancing), not against individual-level
capacity/PTO/burnout tracking or automatic task reassignment this task explicitly declines
to build.
