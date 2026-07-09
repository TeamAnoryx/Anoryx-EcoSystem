# ADR-0016 — Team Capacity Management: Teams, Task Assignment, Utilization, Advisory Rebalancing

- **Status:** Accepted
- **Date:** 2026-07-09
- **Task:** D-016 (Dynamic team / capacity management) · Builder: orchestration-hooks ·
  Phase 3 (post-investment vision) — the fourth task built past Delta's committed MVP
  (D-001→D-012), continuing directly after D-015 per the user's explicit instruction
  to keep going into the vision tier.
- **Depends on:** D-015 (the roadmap's own stated dependency — team capacity is
  meaningless without the sprints/tasks it measures load against; `teams`/task
  assignment are additive extensions of D-015's `tasks` table, not a new work-item
  concept).
- **Builds on:** D-015's forward-only-vs-reopenable lifecycle distinction (not
  applicable here — a team's capacity is a plain mutable number, not a lifecycle),
  D-011's forecasting ADR and D-013's relationship-score ADR's "no ecosystem
  precedent for real ML" reasoning (applied again here for "automated resource
  allocation"), D-014's `reject_non_integer` float-coercion fix (applied proactively
  from the start to `capacity_points_per_sprint`), migration 0006's own precedent of
  additively extending an earlier task's table (`change_history`) after the fact —
  applied here to extend D-015's `tasks` table with a nullable `team_id` column.
- **Supersedes:** nothing. Adds a new `delta.capacity` package, one new table
  (`teams`) plus one additive nullable column (`tasks.team_id`) via migration 0010,
  and one new router mount to `allocation_admin/app.py`; does not alter any
  D-001…D-015 runtime behavior or contract. `delta.pm`'s own source files
  (schemas/store/service/router) are not modified at all by this task.

## 1. Context

The roadmap's literal text for D-016 is: *"Squad performance, capacity tracking,
automated resource allocation, real-time utilization to prevent burnout + optimize
throughput."* Tagged `🏦 POST-INVESTMENT`, sized "16-22h · Risk: Medium." Taken
literally this asks for things this run cannot honestly deliver in one unattended
pass: **individual-level capacity/PTO/burnout tracking** (Delta has no personnel data
model anywhere — the same "no HR" boundary D-014's ADR already drew for payroll/HR),
**automated resource allocation** (an algorithm that moves work on its own — a
meaningfully different, higher-trust claim than a suggestion an operator reviews), and
**real-time** (push/websocket updates — no such infrastructure exists anywhere in
Delta, the same gap D-015's ADR already named). This ADR applies the same discipline
D-013/D-014/D-015 already established: a bounded, honestly-scoped vertical slice —
team-level (not individual) capacity, task-to-team assignment, a deterministic
utilization report, and an advisory (never automatic) rebalancing suggestion.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — team-level capacity only; "automated resource allocation" is a suggestion an operator must apply, never an automatic mutation** | D-016 implements: teams with an operator-declared `capacity_points_per_sprint`, task-to-team assignment (a plain `POST .../tasks/{id}/team`), a deterministic utilization report, and a rebalance-suggestion report. The rebalance report NEVER writes to the database — `service.get_rebalance_report` only reads (`store.get_utilization_rows`, `store.list_movable_tasks`) and returns suggestions; applying one requires the SAME explicit `assign_task_team` call an operator would make manually. | "Automated" carrying an implicit "acts on its own" meaning is a materially different, higher-trust claim than a suggestion a human reviews and applies — the exact distinction D-011's forecasting ADR drew between a projection and an auto-enforced budget cut. An algorithm that silently reassigns a team's work without review is a real operational risk (moving the wrong task, at the wrong time, with no human check) this task is not positioned to responsibly ship in one unattended pass. |
| **2 — capacity is declared at the TEAM level, never inferred from individuals** | `teams.capacity_points_per_sprint` is a single operator-entered integer per team — there is no per-person capacity, no calendar/PTO integration, no hours-worked tracking anywhere in `delta.capacity`. | Mirrors D-014's ADR Fork 1 exactly (payroll/HR excluded: sensitive PII, no existing data model, no compliance review this run can provide). Team-level capacity is a natural extension of Delta's existing "track money and things tied to it" competency (now extended to "and the work items tied to it," via D-015); individual capacity/PTO is categorically different and is named as deferred, not approximated. |
| **3 — `tasks.team_id` is an additive nullable column on D-015's existing table, not a new join table, and `delta.pm`'s own files are never modified** | Migration 0010 does `op.add_column("tasks", sa.Column("team_id", ...))` — the exact `op.add_column`-on-an-earlier-table shape migration 0006 already used to extend `change_history`. `delta.capacity.store`/`service`/`router` read and write `tasks.team_id` directly (via the shared `persistence.models.tasks` table object); no file under `delta/pm/` is touched. | A join table (`task_team_assignments`) would model "a task can belong to multiple teams over time" — a real feature this task does not claim (one task has at most one current team, matching one task having at most one current sprint in D-015's own `tasks.sprint_id` shape). Not touching `delta/pm/*.py` at all (only the shared table definition in `persistence/models.py` gains one column) keeps this task's diff auditable as a clean superset — D-015's own runtime behavior, tests, and contract are provably unaffected. |
| **4 — utilization measures REMAINING (not-done) assigned story points against capacity, not total lifetime assignment** | `get_utilization_rows` reports both `total_assigned_points` (every task ever assigned to the team this sprint, any status) and `remaining_points` (only `status != 'done'`); `utilization_ratio` is computed from `remaining_points`. | A team's actual current load is what's still outstanding, not everything they've ever touched — a team that finished all its assigned work should read as fully available (0% utilized), not permanently "at capacity" because of past completed tasks. Both numbers are still surfaced (not silently dropped) so an operator can see full context. |
| **5 — a zero-capacity team with outstanding work reports `utilization_ratio: null`, never a divide-by-zero or a fabricated number** | `service.get_utilization_report`: `capacity > 0` → real ratio; `capacity == 0 and remaining > 0` → `None` (undefined); `capacity == 0 and remaining == 0` → `0.0`. | An honest "this number is undefined" is categorically better than silently returning `inf`, `NaN`, or a divide-by-zero exception — the same "never a silently-wrong number" discipline this session applies to every computed metric (mirrors D-011's forecasting ADR's own handling of a zero-denominator edge case). |
| **6 — the rebalance suggestion is a deterministic greedy heuristic (`greedy_rebalance_v1`), not a trained/validated ML optimization** | `service._greedy_rebalance` (a pure function, no DB — mirrors `pm.service._would_create_cycle`'s pure-traversal shape for the same testability reason) sorts over-capacity teams by excess descending, picks the largest not-done task from each, and assigns it to whichever under-capacity team currently has the most spare capacity, repeating until each over-capacity team's excess clears or its movable tasks run out. | Same "no ecosystem precedent for real ML" reasoning as D-011/D-012/D-013/D-015 — a fixed, explainable, versioned algorithm is the honest substitute for "optimize throughput." Returns plain dataclasses (not the Pydantic wire DTO) so the function stays dependency-free and directly unit-testable with arbitrary non-UUID-shaped test ids; `get_rebalance_report` maps to the wire DTO. |
| **7 — mounted on the existing admin app, not a new process** | `GET/POST /v1/admin/capacity/*` on the same D-007 admin app, same `require_admin` break-glass bearer auth (imported unchanged from `allocation_admin.auth`). | Same operators, same auth, same trust boundary — mirrors D-008/D-011/D-012/D-013/D-014/D-015's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No individual-level capacity, PTO, or working-hours tracking.** Capacity is
  declared once per team, not derived from any person's calendar, time-off, or hours
  worked — Delta has no personnel data model anywhere (mirrors D-014's "no HR"
  boundary exactly).
- **No burnout or wellbeing measurement.** `utilization_ratio` is a workload-vs-
  declared-capacity ratio, nothing more — it is not validated against, and does not
  claim to predict, human burnout, stress, or wellbeing. The roadmap's "prevent
  burnout" framing is honestly narrowed to "surface when a team's outstanding work
  exceeds its declared capacity," a much smaller and truthful claim.
- **No automatic task reassignment.** The rebalance report is read-only; every
  suggestion requires an explicit operator action (the same `assign_task_team`
  endpoint used for any manual reassignment) to take effect. Named explicitly in Fork
  1 — this is the single most important honesty boundary in this task.
- **No trained/validated ML for the rebalance suggestion.** `greedy_rebalance_v1` is a
  fixed, deterministic, versioned heuristic — not a statistical or machine-learning
  model, not trained on historical outcomes, not validated against real throughput
  data.
- **No cross-project team capacity view.** Utilization and rebalance reports are
  scoped to one `project_id` + `sprint_id` per request, matching D-015's own report
  scoping — no portfolio-level or multi-project capacity rollup.
- **No capacity history or trend tracking.** `teams.capacity_points_per_sprint` is the
  team's CURRENT declared capacity only — no historical record of past capacity
  values, no trend analysis over multiple sprints.
- **No squad "performance" scoring of any kind.** Nothing in `delta.capacity`
  evaluates how well a team or individual performed — that is HR/performance-review
  territory this task does not enter, matching D-013/D-014's own boundary.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant team/task-assignment leak | Every query runs on the caller's tenant-scoped (RLS) `AsyncSession`; `teams`' RLS predicate is the same fail-closed `tenant_id = NULLIF(current_setting(...), '')` as every prior Delta migration | `test_cross_tenant_isolation_teams_invisible_to_other_tenant`, `test_cross_tenant_team_list_isolated_over_http` |
| A task is assigned to a team from a DIFFERENT tenant | Structurally impossible: `fk_task_team` is a composite `(team_id, tenant_id)` FK against `teams`'s `uq_team_id_tenant`, which is itself RLS-confined at write time | code review — same FK shape D-007/…/D-015 already establish and tested |
| Capacity-as-float leaking into a count path | `capacity_points_per_sprint` rejects a wire float outright via `mode="before"` + `delta.money.reject_non_integer` (applied proactively, mirroring D-014's audit-driven fix and D-015's proactive application) — no `float` anywhere in `delta.capacity` | `test_team_create_rejects_float_capacity`, `test_team_capacity_update_rejects_float` |
| Utilization report resource amplification | One bounded SQL aggregate query (`outerjoin` + `GROUP BY` + conditional `SUM`/`FILTER` inside Postgres) — never a per-team Python loop | code review — same query shape as D-015's velocity/bottleneck reports, already reviewed for this class of issue |
| Rebalance suggestion resource amplification | `list_movable_tasks` is one query scoped to a single project+sprint, bounded by `limit` (default `DEFAULT_LIST_LIMIT`); `_greedy_rebalance` runs in memory over the (small, sprint-scoped) result — no unbounded loop or per-team query | code review |
| Divide-by-zero / fabricated ratio on a zero-capacity team | `utilization_ratio` is explicitly `None` when capacity is 0 and load is nonzero, `0.0` when both are zero — never a raw Python division that could raise or silently return `inf` | `test_utilization_report_zero_capacity_with_load_is_undefined_ratio` |
| The rebalance report accidentally mutates state | `get_rebalance_report`/`_greedy_rebalance` only call `store.get_utilization_rows`/`store.list_movable_tasks` (both read-only SELECTs) — no `insert`/`update` anywhere in the call path | `test_rebalance_report_suggests_moving_from_over_to_under_team` (explicitly asserts the task's team is UNCHANGED after generating a suggestion) |
| Log-injection / control-character injection via free-text fields | Every free-text field (`name`) goes through the same `_reject_control_chars` discipline as D-007/…/D-015 | `test_team_create_rejects_control_chars_in_name` |
| Auth bypass on any of the 6 new endpoints | `require_admin` (D-007's break-glass bearer, unmodified) is the router-level `dependencies=[Depends(require_admin)]` on the whole `capacity_router` — no per-route opt-out exists | `test_teams_endpoint_401_without_bearer` |
| SQL injection via any capacity identifier or free-text field | Every query is a parameterized SQLAlchemy Core statement — no raw string-interpolated SQL anywhere in `delta.capacity.store` | code review |

## 5. Verification

- `black --check` / `ruff check .` clean on `src/delta/capacity` and `tests/capacity`.
- New `tests/capacity/` suite: 38 tests — 11 pure schema-validation tests
  (`test_schemas.py`), 9 pure greedy-rebalance unit tests (`test_greedy_rebalance.py`,
  no DB/I/O), 8 DB-backed store tests (`test_store_db.py`), 6 DB-backed service tests
  (`test_service_db.py`, incl. the zero-capacity and rebalance-is-read-only tests), 5
  non-stubbed HTTP e2e tests (`test_router_e2e.py`, real ASGI app, real auth, real DB).
- Full existing Delta suite green (751 passed, 15 skipped) — zero regressions, zero
  changes to any D-001…D-015 file's runtime behavior. The only modifications to
  existing code are one router mount in `allocation_admin/app.py`, one new section in
  `identifiers.py` (a comment only — no new identifier type), and one new table plus
  one new nullable column in `persistence/models.py` (additive only) — `delta/pm/*.py`
  is untouched by this task.
- Migration 0010 verified round-trip (`alembic upgrade head` → `downgrade -1` →
  `upgrade head`) against a live local Postgres, `delta_app` role provisioned exactly
  as every prior migration's test harness does.
- Frontend: `npx tsc --noEmit` clean, `eslint` clean (0 warnings/errors on all new/
  modified files), `npm run build` succeeds (`/capacity` registered as a dynamic
  route), and the frontend's own `vitest` suite (45 tests) stays green. Live browser
  smoke test performed against a real running backend with real data entered through
  the UI itself: created a sprint and an 8-point task (via the existing `/pm` page),
  created an "Overloaded" team (capacity 5) and a "Spare" team (capacity 10), assigned
  the task to Overloaded, confirmed the utilization report showed 160% (8/5) for
  Overloaded, confirmed the rebalance report suggested moving the task to Spare,
  clicked Apply, and confirmed both that the rebalance report emptied afterward AND
  that the task's team-assignment select now showed Spare's id — proving the "advisory
  only, applied via the same manual endpoint" design (Fork 1) actually works ​
  end-to-end, not just at the API layer.
- A design gap was caught and fixed before the smoke test: the initial page draft
  hard-coded the task-assignment table's "current team" as `null` because D-015's own
  `TaskView` does not expose `team_id` (by design — `delta.pm` never reads/writes that
  column, Fork 3). Fixed by adding a dedicated `GET /v1/admin/capacity/tasks` endpoint
  (`TaskCapacityView`, `store.list_tasks_for_capacity`) that the capacity UI reads
  through instead of `/v1/admin/pm/tasks` whenever it needs a task's current team —
  covered by `test_list_tasks_for_capacity_reflects_team_assignment` and an assertion
  in the HTTP e2e flow test.
- Independent security-auditor review: verdict **CLEAN** — no High, Critical, Medium,
  or Low findings. The reviewer explicitly re-checked whether either of D-015's two
  audit-confirmed bug classes (a TOCTOU race with no DB backstop; a query helper
  silently routed through the wrong, smaller limit constant) recur here and
  disproved both by reproduction/trace: this feature has no check-then-write path
  guarding a cross-row invariant (every write is a single unconditional INSERT/
  UPDATE, so a 10-way concurrent race against `assign_task_team` produced 10 clean
  successes with no invariant to violate), and every `store.py` list helper routes
  through its own correctly-scoped limit constant. Cross-tenant task-team assignment
  was proven structurally impossible even when bypassing the service-layer check
  entirely (a raw cross-tenant `store.assign_task_team` call was rejected by the
  `fk_task_team` composite FK itself). Full findings in
  `docs/audit/d-016-security-audit.md`.

## 6. Alternatives considered

- **Automatically applying rebalance suggestions without operator review.** Rejected
  (Fork 1): a materially higher-trust claim than a reviewed suggestion, and a real
  operational risk (silently moving the wrong work at the wrong time) this task is not
  positioned to responsibly ship unattended. The roadmap's own "automated resource
  allocation" framing is honestly narrowed to "an automated SUGGESTION, manually
  applied."
- **Individual-level capacity, PTO, or calendar integration.** Rejected (Fork 2) for
  the identical reason D-014 declined payroll/HR: sensitive personnel data, no
  existing data model, no compliance review this run can provide.
- **A `task_team_assignments` join table instead of an additive `tasks.team_id`
  column.** Rejected (Fork 3): a join table would model multi-team task ownership — a
  real feature this task does not claim. The additive-column shape also keeps
  `delta/pm/*.py` completely untouched, which is a stronger auditability guarantee
  than a join table would provide.
- **Utilization measured against total lifetime assignment instead of remaining
  (not-done) work.** Rejected (Fork 4): would make a team that finished all its work
  read as permanently overloaded, which misrepresents actual current capacity.
- **A trained/validated ML model for the rebalance suggestion.** Rejected (Fork 6) for
  the identical reason D-011/D-012/D-013/D-015 all declined it: no labeled training
  data, no validation harness, no ecosystem precedent.
