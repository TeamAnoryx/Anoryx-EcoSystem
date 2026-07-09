# ADR-0015 — Project Management: Sprints, Tasks, Dependency Mapping

- **Status:** Accepted
- **Date:** 2026-07-09
- **Task:** D-015 (AI-driven project management) · Builder: orchestration-hooks ·
  Phase 3 (post-investment vision) — the third task built past Delta's committed MVP
  (D-001→D-012), continuing directly after D-014 per the user's explicit instruction
  to keep going into the vision tier.
- **Depends on:** D-001 (identifier/domain-type conventions), D-008 (indirectly — the
  roadmap names it as a dependency; D-015 does not call into `delta.dashboards`
  directly, but "sprint velocity" is the same aggregate-reporting shape D-008
  established: one bounded SQL query per report, never a per-row Python loop).
- **Builds on:** D-013's forward-only-vs-reopenable lifecycle distinction (applied in
  reverse here — task status is deliberately reopenable, unlike D-013's deal stages),
  D-013/D-014's value/currency-pairing lesson (not applicable here — D-015 has no
  money fields), D-014's `reject_non_integer` float-coercion fix (applied proactively
  from the start to `story_points`, not post-audit).
- **Supersedes:** nothing. Adds a new `delta.pm` package, three new tables (migration
  0009), and one new router mount to `allocation_admin/app.py`; does not alter any
  D-001…D-014 runtime behavior, contract, or persistence schema.

## 1. Context

The roadmap's literal text for D-015 is: *"Sprint-velocity tracking, dependency
mapping, execution-bottleneck prediction. Real-time, integrates with client/team-set
project parameters."* Tagged `🏦 POST-INVESTMENT`, sized "22-30h · Risk: Medium." Taken
literally this asks for three things this run cannot honestly deliver in one
unattended pass: **real-time** (push/websocket updates — no such infrastructure exists
anywhere in Delta), **prediction** (a trained/validated ML forecasting model — the
exact class of feature D-011's ADR already declined, for the same reason: no
ecosystem precedent, no labeled training data, no validation harness), and full
external-tool parity implied by "project management" as a category (Jira/Linear/GitHub
Issues-level feature breadth). This ADR applies the same discipline D-013 and D-014
already established: a bounded, honestly-scoped vertical slice, not the label's full
literal breadth — sprints, tasks, a real dependency graph, a real velocity aggregate,
and a deterministic (not ML) bottleneck heuristic.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — sprints + tasks + a real dependency graph + two aggregate reports; no real-time push, no external issue-tracker integration** | D-015 implements: sprint CRUD (create + status update), task CRUD (create + status update) optionally scoped to a sprint, a `task_dependencies` edge table with cycle rejection, a sprint-velocity report, and a blocking-fan-out bottleneck report. It does not add websockets/polling infrastructure, and does not integrate with Jira, Linear, GitHub Issues, or any external tracker. | No push/real-time infrastructure exists anywhere in Delta's stack (every prior admin surface — D-007 through D-014 — is plain request/response HTTP); inventing one, unreviewed, for this task alone would be new infrastructure risk far outside a bounded vertical slice. External issue-tracker integration has zero precedent anywhere in the Anoryx ecosystem and no named future roadmap task to hand it off to (unlike D-014's ERP, which explicitly hands "real sync" to D-019) — it is simply out of scope, named honestly in §3. |
| **2 — task status is deliberately reopenable (todo/in_progress/blocked/done), NOT forward-only like D-013's deal stages or D-014's asset lifecycle** | `update_task_status` applies any requested status unconditionally (no `required_prior` guard); `completed_at` is stamped when the new status is `"done"` and cleared (set to `None`) for every other status, unconditionally, on every transition. | A task naturally bounces between states in real project work (reopened after a regression, moved back to in_progress after review feedback) — unlike a deal pipeline or an asset's physical lifecycle, there is no real "you can never go back" invariant to enforce here. Sprint status (`planned`/`active`/`completed`) is the same shape for the identical reason: a sprint can be reactivated after being marked complete by mistake. |
| **3 — the dependency graph is cycle-free by service-layer BFS, not a DB constraint** | `create_dependency` loads all of the tenant's dependency edges (bounded to `MAX_DEPENDENCY_EDGES_CONSIDERED = 2000`) and runs `_would_create_cycle` (a BFS from the new edge's `blocked` task, checking whether the new edge's `blocking` task is reachable) before inserting; rejected with a 422 if it would close a cycle. | Postgres has no native "this edge table must remain acyclic" constraint — a `CHECK` can only see one row at a time, and a cycle is a property of the whole graph. This is a genuinely novel piece of logic with no precedent in D-007→D-014, so it received the most dedicated pure-unit-test attention of any single function in this task (8 pure BFS tests covering direct/transitive/diamond-shaped/long-chain cases, plus 1 DB-backed integration test building a real 3-node chain and confirming the closing edge is rejected). The 2000-edge bound exists so a pathologically large graph cannot turn this into an unbounded per-request scan — named as a real (if generous) limit, not silently unenforced. |
| **4 — "execution-bottleneck prediction" is a deterministic blocking-fan-out heuristic (`blocking_fanout_v1`), not a trained/validated ML model** | `get_bottleneck_report` ranks non-`done` tasks by how many *other* tasks they directly block (`COUNT` via a `LEFT JOIN` on `task_dependencies`, `GROUP BY`, `HAVING count > 0`, `ORDER BY count DESC`) — a single bounded SQL query, not a Python loop. The response carries an explicit `method: Literal["blocking_fanout_v1"] = "blocking_fanout_v1"` field and a docstring stating plainly this is not ML. | Mirrors D-011's forecasting ADR and D-013's `recency_frequency_v1` relationship score exactly: this session has no labeled training data, no validation harness, and no ecosystem precedent for a real statistical/ML model for any of these "AI-driven" roadmap labels. A fixed, explainable, versioned heuristic is the honest substitute — "high-coverage detection"/"likely" language, never a false claim of prediction (this repo's own honest-language mandate). |
| **5 — velocity and bottleneck reports are each ONE bounded SQL query, never a per-row Python loop** | `get_velocity_report` does one `outerjoin(sprints, tasks)` with `func.coalesce(func.sum(...).filter(...), 0)`/`func.count(...).filter(...)`, `GROUP BY sprint_id, name, status`. `get_bottleneck_report` does one `outerjoin(tasks, task_dependencies)`, filtered to non-done tasks, `GROUP BY`, `HAVING`, `ORDER BY`. | Same O(1)-queries-per-request discipline D-011/D-012's security reviews already established and which D-013/D-014 applied proactively from the first draft — a report that fans out into N+1 queries as the project grows is a resource-amplification risk a single aggregate query structurally cannot have. |
| **6 — task/sprint edits are NOT wired into D-009's hash-chained audit log** | Unlike D-014's purchase-order decisions (wired into D-009 in the same transaction as the store write), creating/updating a sprint or task does not call `delta.persistence.audit_log.append_history`. | Mirrors D-013's CRM reasoning exactly: a task edit is business-process data, not a financial transaction — D-009's own stated scope is Delta's *automated financial workflows*. The roadmap's own dependency line for D-015 lists only `D-001, D-008` — notably omitting D-009, unlike D-014's explicit `D-009` dependency — which independently supports this boundary. |
| **7 — `story_points` rejects a wire float outright from the first draft, not post-audit** | `TaskCreateRequest.story_points` uses a `mode="before"` field validator delegating to `delta.money.reject_non_integer`, exactly like D-014's audit-driven fix for `acquisition_cost_minor_units`/`amount_minor_units`. | D-014's own independent security review caught this exact class of bug (Pydantic silently coercing `100.0` → `int(100)` on a plain `int = Field(...)` count field) after the fact. This task applies that lesson proactively rather than needing its own audit to catch it — the same discipline D-014 itself applied for D-013's value/currency lesson. |
| **8 — mounted on the existing admin app, not a new process** | `GET/POST /v1/admin/pm/*` on the same D-007 admin app, same `require_admin` break-glass bearer auth (imported unchanged from `allocation_admin.auth`). | Same operators, same auth, same trust boundary — mirrors D-008/D-011/D-012/D-013/D-014's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No real-time push updates.** No websocket, no server-sent events, no polling
  infrastructure. Every PM read is a plain request/response HTTP call — a client that
  wants fresher data re-fetches, exactly like every other Delta admin surface. Building
  a live-update channel unreviewed, for this task alone, is out of scope (Fork 1).
- **No external issue-tracker integration.** No Jira, Linear, GitHub Issues, or any
  other external system sync — sprints/tasks/dependencies exist only inside Delta's own
  schema. Unlike D-014's ERP (which hands real external sync to the explicitly
  dependent D-019), no future roadmap task currently claims this — named honestly here
  as unclaimed future work, not approximated.
- **No trained/validated ML bottleneck prediction.** `blocking_fanout_v1` is a fixed,
  deterministic ranking by direct blocking count — not a statistical or machine-learning
  model, not trained on historical completion data, not validated against real outcomes.
  Mirrors D-011's forecasting ADR and D-013's relationship-score ADR's identical
  "no ecosystem precedent for real ML" reasoning.
- **No burndown charts, capacity planning, or story-point estimation assistance.**
  The velocity report is a per-sprint completed-points/completed-task-count/total-task-
  count summary only — no day-by-day burndown curve, no team-capacity modeling (that is
  D-016's explicitly separate roadmap scope: "Dynamic team / capacity management"), no
  estimation-assistance feature of any kind.
- **No sub-tasks, epics, labels, or custom fields.** A task is a single flat row
  (title, status, story points, assignee, optional sprint). No hierarchical work
  breakdown, no tagging/labeling system, no custom-field schema.
- **No comments, attachments, or activity feed on a task.** A task's mutable surface
  is its status only (plus the fields set at creation) — no threaded discussion, no file
  attachments, no per-task history view beyond `updated_at`.
- **No multi-project cross-dependency view.** The dependency graph and both reports are
  scoped to a single `project_id` per request — there is no cross-project dependency
  visualization or portfolio-level rollup.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant sprint/task/dependency leak | Every query runs on the caller's tenant-scoped (RLS) `AsyncSession`; every table's RLS predicate is the same fail-closed `tenant_id = NULLIF(current_setting(...), '')` as every prior Delta migration; every FK is a composite `(entity_id, tenant_id)` pair | `test_cross_tenant_isolation_sprints_invisible_to_other_tenant`, `test_cross_tenant_sprint_list_isolated_over_http` |
| A task references a sprint from a DIFFERENT tenant | Structurally impossible: `tasks`'s FK to `sprints` is a composite `(sprint_id, tenant_id)` pair against `sprints`'s `UniqueConstraint(sprint_id, tenant_id)`, which is itself RLS-confined at write time | code review — same FK shape D-007/D-013/D-014 already establish and tested |
| A dependency edge closes a cycle in the task graph | `create_dependency` loads all existing edges (bounded, `MAX_DEPENDENCY_EDGES_CONSIDERED = 2000`) and runs `_would_create_cycle` (BFS) before inserting — a 422 on any edge that would create one | 8 pure `test_cycle_detection.py` tests (direct/transitive/diamond/long-chain, both cyclic and non-cyclic cases), `test_create_dependency_cycle_rejected_against_real_graph` (real 3-node A→B→C chain, real DB, real rejection of the closing C→A edge), `test_dependency_cycle_returns_422_over_http` |
| A task blocks itself | `create_dependency` checks `blocking_task_id == blocked_task_id` before ever touching the graph, raising `SelfDependencyError` → 422 | `test_create_dependency_self_reference_raises`, `test_self_dependency_returns_422_over_http` |
| `completed_at` drifts out of sync with `status` | `update_task_status` unconditionally sets `completed_at = now` when the new status is `"done"` and `None` otherwise, in the same store call/transaction as the status write — a DB `CHECK ((status = 'done') = (completed_at IS NOT NULL))` is a second, independent layer | `test_task_status_done_sets_completed_at_and_reopening_clears_it` |
| Story-points-as-float leaking into a count path | `story_points` rejects a wire float outright via `mode="before"` + `delta.money.reject_non_integer` (applied proactively, mirroring D-014's audit-driven fix) — no `float` anywhere in `delta.pm` | `test_task_create_rejects_float_story_points` |
| Bottleneck/velocity report resource amplification as a project grows | Each report is exactly one bounded SQL aggregate query (`GROUP BY`/`HAVING`/`ORDER BY` inside Postgres) — never a per-row Python loop; `limit` is bounded (`DEFAULT_LIST_LIMIT = 100`, `MAX_LIST_LIMIT = 500`) on every list/report endpoint | code review — same query shape as D-008's dashboards/D-011's forecasting, both already reviewed for this class of issue |
| Naive (non-UTC-aware) timestamps silently misinterpreted | `require_aware_utc` (D-001's own helper, reused unchanged) on `start_date`/`end_date` | `test_sprint_create_rejects_naive_start_date`, `test_sprint_create_rejects_naive_end_date` |
| Log-injection / control-character injection via free-text fields | Every free-text field (`name`, `title`, `assignee`) goes through the same `_reject_control_chars` discipline as D-007/D-013/D-014 | `test_sprint_create_rejects_control_chars_in_name`, `test_task_create_rejects_control_chars_in_title`, `test_task_create_rejects_control_chars_in_assignee` |
| Auth bypass on any of the 9 new endpoints | `require_admin` (D-007's break-glass bearer, unmodified) is the router-level `dependencies=[Depends(require_admin)]` on the whole `pm_router` — no per-route opt-out exists | `test_sprints_endpoint_401_without_bearer` |
| SQL injection via any PM identifier or free-text field | Every query is a parameterized SQLAlchemy Core statement — no raw string-interpolated SQL anywhere in `delta.pm.store` | code review |

## 5. Verification

- `black --check` / `ruff check .` clean on `src/delta/pm` and `tests/pm`.
- New `tests/pm/` suite: 41 tests — 16 pure schema-validation tests (`test_schemas.py`),
  8 pure cycle-detection tests (`test_cycle_detection.py`, no DB/I/O), 5 DB-backed store
  tests (`test_store_db.py`), 7 DB-backed service tests (`test_service_db.py`, incl. the
  real-graph cycle-rejection integration test), 5 non-stubbed HTTP e2e tests
  (`test_router_e2e.py`, real ASGI app, real auth, real DB).
- Full existing Delta suite green (710 passed, 15 skipped) — zero regressions, zero
  changes to any D-001…D-014 file's runtime behavior (the only modification to existing
  code is one router mount in `allocation_admin/app.py`, and one new section each in
  `identifiers.py`/`persistence/models.py`, additive only).
- Migration 0009 verified round-trip (`alembic upgrade head` → `downgrade -1` →
  `upgrade head`) against a live local Postgres, `delta_app` role provisioned exactly as
  every prior migration's test harness does.
- Frontend: `npx tsc --noEmit` clean, `eslint` clean (0 warnings/errors on all new/
  modified files), `npm run build` succeeds (`/pm` registered as a dynamic route), and
  the frontend's own `vitest` suite (45 tests) stays green. Live browser smoke test
  performed against a real running backend with real data entered through the UI
  itself: logged in via the break-glass token, created a sprint, created two tasks
  assigned to that sprint, linked a "blocks" dependency between them, confirmed the
  bottleneck report surfaced the blocking task with `blocking_count: 1` and
  `method: "blocking_fanout_v1"`, marked the blocking task done, confirmed the
  bottleneck report emptied, and confirmed the velocity report showed
  `completed_story_points: 3`, `1 / 2` tasks done — all matching the backend e2e test's
  own assertions exactly.
- Independent security-auditor review: scheduled next (dispatched after this ADR is
  committed, per the established D-013/D-014 procedure) — findings and fixes, if any,
  will be recorded in `docs/audit/d-015-security-audit.md` before this branch merges.

## 6. Alternatives considered

- **Building real-time push updates (websocket/SSE) for live dependency/bottleneck
  state.** Rejected (Fork 1): no such infrastructure exists anywhere in Delta, and
  inventing one unreviewed for this task alone is new infrastructure risk far outside a
  bounded vertical slice — every other Delta admin surface is plain request/response.
- **Integrating with an external issue tracker (Jira/Linear/GitHub Issues) now.**
  Rejected (Fork 1): zero ecosystem precedent, and unlike D-014's ERP (which names
  D-019 as the explicit future integration task), no roadmap task currently claims this
  — named as unclaimed future work in §3 rather than attempted unreviewed.
- **A trained/validated ML model for bottleneck or completion-time prediction.**
  Rejected (Fork 4) for the identical reason D-011's forecasting ADR and D-013's
  relationship-score ADR both declined it: no labeled training data, no validation
  harness, no ecosystem precedent — a deterministic, versioned, explainable heuristic is
  the honest substitute.
- **A DB CHECK-based approach to cycle prevention (e.g. a materialized closure table
  with a trigger).** Rejected (Fork 3): Postgres has no native whole-graph acyclicity
  constraint, and a trigger-maintained transitive-closure table is meaningfully more
  complex and harder to reason about than a bounded service-layer BFS run once per
  mutating request — the bound (`MAX_DEPENDENCY_EDGES_CONSIDERED`) gives the same
  practical safety without the added schema/trigger complexity.
- **Making task status forward-only, mirroring D-013/D-014's lifecycles.** Rejected
  (Fork 2): unlike a deal pipeline or an asset's physical lifecycle, a task's real-world
  states genuinely bounce back and forth (reopened, sent back for review) — forcing a
  forward-only model would misrepresent how project work actually happens.
- **Wiring task/sprint edits into D-009's hash-chained audit log, mirroring D-014's
  purchase-order decisions.** Rejected (Fork 6): a task edit is business-process data,
  not a financial transaction — the roadmap's own dependency line for D-015 (`D-001,
  D-008`) notably omits D-009, unlike D-014's explicit dependency on it.
