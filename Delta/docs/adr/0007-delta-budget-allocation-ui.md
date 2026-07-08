# ADR-0007 — Delta Budget Allocation Admin (API + console)

- **Status:** Proposed (awaiting human approval — STEP 1 gate)
- **Date:** 2026-07-07
- **Task:** D-007 (Budget allocation UI) · Builder: frontend (backend admin surface built alongside
  it — see §1 honest scope note)
- **Builds on:** D-001 (`allocation.py` domain type), D-002 (`budget_policy.py`), D-005
  (`budget_engine.definitions.create_budget`, the internal seam this task exposes)
- **Delta ADR head is 0006; this is 0007.**

---

## 1. Context — honest scope note

The roadmap describes D-007 in one line: "Admin console for distributing budgets, approval
workflows, change history." In reality, **no admin HTTP surface, approval-workflow model, or
change-history model existed anywhere in Delta before this task** — only the internal-only
`budget_engine.definitions.create_budget` seam (D-005), whose own module docstring says
verbatim: *"Budgets are seeded via `create_budget` (an internal create path; the full allocation
UI is D-007)."* So D-007 is materially: design + build a new Delta admin HTTP API (auth,
allocation propose/approve/reject, change-history log) **and** the Next.js/BFF console in front
of it — stated here up front rather than implied away (banked rule #14).

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — never auto-apply** | Proposing an allocation NEVER touches `budget_definitions`. Only an explicit `approve` decision materializes each target into a real budget cap via the unchanged D-005 `create_budget` seam. | This IS the approval workflow the roadmap asks for: propose is reversible and inert; only a second, distinct action has effect. No new budget-creation code path — D-007 calls the existing, already-audited D-005 function. |
| **2 — approval state lives on the allocation itself** | `allocations.status` is the state machine (`requested -> approved | rejected`), not a separate generic "approvals" entity. | A separate `approvals` table would be a redundant join for a 1:1 relationship nothing else in the codebase needs yet (banked rule #13 — lean STEP-0 fork, smaller surface). The allocation *is* the thing under approval; over-generalizing to a reusable approval-entity system is speculative design for a demand that doesn't exist. |
| **3 — auth: single break-glass bearer** | One deploy-injected `DELTA_ADMIN_TOKEN`, constant-time compared (mirrors Sentinel F-012a `require_admin`), no SSO/operator-session tier. | Delta has no existing operator-identity system to federate an SSO tier against (unlike Sentinel's ADR-0017, built on Sentinel's own SSO). A second credential tier here would be speculative infrastructure for a threat model (multi-operator attribution) this task doesn't yet have — the lean default per rule #13. `actor`/`requested_by`/`decided_by` are free-text fields the caller supplies, not an authenticated operator identity; this is an honest limitation, not a design gap (see §7). |
| **4 — per-target admin session, not a global admin identity** | Every route takes an explicit `tenant_id` and opens `get_tenant_session(tenant_id)` for that one call — the operator explicitly targets one tenant per call, RLS-enforced through the same `delta_app` (NOBYPASSRLS) role every tenant request uses. | Mirrors Sentinel F-012a's "per-target `get_tenant_session`" pattern. The admin bearer authenticates the OPERATOR, never widens data access — RLS is enforced by the role regardless of caller identity (defense in depth: even a confused/compromised admin token cannot cross tenants without a tenant_id the operator supplies, and cannot cross tenants even then, since the underlying role is NOBYPASSRLS). |
| **5 — change-history is a plain log, NOT hash-chained** | `change_history` is append-only (INSERT/SELECT only grant, no UPDATE/DELETE for `delta_app`) but carries no hash chain. | The tamper-evident, hash-chained financial-workflow audit trail is a separate, later, ecosystem-wide task — **D-009**, applying the Sentinel F-003 pattern to Delta. Building a hash chain inside D-007 would be scope creep into D-009's territory and a premature, partial version of a guarantee D-009 is meant to deliver properly. This log is its honest, un-hash-chained precursor (banked rule #14 — do not imply a stronger guarantee than what's built). |
| **6 — reconciliation validated via the existing D-001 type, not reimplemented** | `service.create_allocation_request` constructs a real `delta.allocation.Allocation` (with a placeholder `allocation_id` used only for the validation side effect) so the "targets sum to total, same currency" invariant (vector 4) is enforced by the SAME model D-001 already proved, not a second implementation that could drift. | Reuse over reinvention; the domain type was previously unused anywhere in the codebase (its own docstring: D-007 is very likely where it finally gets exercised). |
| **7 — double-decision race is a real 409, not a silent no-op or a second material effect** | `try_decide_allocation` does a conditional `UPDATE ... WHERE status='requested'`; a concurrent second decision affects zero rows and the caller gets `AllocationAlreadyDecidedError` -> HTTP 409. | Same race class + same fix shape as D-005's `budget_enforcement_state` conditional transition and D-006's `kill_switch_state` transition — two operators racing to decide the same allocation must not both materialize budgets (double-spend the same total) or silently overwrite each other's decision. |
| **8 — frontend is a real Next.js BFF console, not a static admin page** | `Delta/frontend/`: Next.js App Router + TypeScript + Tailwind, mirroring Sentinel's F-012 BFF-only pattern (root `CLAUDE.md` rule #10) — session cookie only in the browser, the bearer is attached server-side only. | The Orchestrator's O-007 admin UI deliberately chose a dependency-free static page because Orchestrator "has no such scaffold, no npm toolchain" (ADR 0007, Orchestrator) — that reasoning does not transfer here: D-007's own builder role is explicitly "frontend," and Sentinel's proven Next.js/BFF scaffold is the established sibling pattern to copy, not reinvent from scratch. |
| **9 — no docker-compose service wiring in this task** | `Delta/frontend/` and the new `delta.allocation_admin.app` are runnable via `npm run dev` / `uvicorn`, documented in README, but NOT wired into `Delta/docker-compose.yml`. | Precedent: D-004's ingest app, D-005's engine, and D-006's kill-switch ALL ship with zero docker-compose service either — Delta's compose file today stands up only Postgres + a one-shot migration container. Full service wiring for every Delta HTTP surface is D-010 ("Deployment," depends on D-005 + F-010), not each feature task individually. Wiring one service now while every other Delta app has none would be inconsistent, undocumented scope creep into D-010's job. |

## 3. Architecture

### 3.1 Backend — `Delta/src/delta/allocation_admin/`

```
config.py    fail-loud DELTA_ADMIN_TOKEN resolution (mirrors ingest/kill_switch config.py)
auth.py      require_admin: constant-time bearer compare -> request.state.admin_principal
schemas.py   wire DTOs (AllocationCreateRequest, AllocationView, ApprovalDecisionRequest, ...)
store.py     SQLAlchemy Core reads/writes against allocations/allocation_targets/change_history;
             caller-owns-the-transaction (does not commit), exactly like budget_engine.definitions
service.py   propose -> validate (delta.allocation.Allocation) -> persist 'requested' -> history;
             decide -> conditional transition -> (approve: create_budget per target) -> history
router.py    POST/GET /v1/admin/allocations, POST .../decision, GET /v1/admin/history
app.py       create_app() factory: fail-loud settings, /health, no public OpenAPI schema
```

### 3.2 Frontend — `Delta/frontend/`

Next.js App Router, mirroring `Anoryx-Sentinel/frontend/`'s BFF spine: `src/lib/env.ts` (the only
`process.env` reader), `src/lib/admin-client.ts` (server-only, the only place the bearer is
attached), `src/lib/bff.ts` (`handleAdminProxy`, path allow-listed, fail-closed), `src/lib/
session.ts` + `session-token.ts` (HMAC-signed httpOnly/Secure/SameSite=Strict cookie, no bearer
ever reaches the browser). Mutating pages use Next.js Server Actions calling `adminApi` directly
(still server-side only, still never exposes the token) rather than a client-side fetch through
the proxy route for the app's own pages; the `/api/admin/[...path]` proxy route is still built and
tested as the documented seam (CLAUDE.md rule #10) for any future non-page client. See
`Delta/frontend/README.md` for the exact page list and required environment.

### 3.3 Data model (migration 0005, down_revision "0004")

- **`allocations`** — the propose/decide state machine. `status IN ('requested','approved',
  'rejected')`; a CHECK ties `decided_by`/`decided_at` presence exactly to non-'requested' status
  (`ck_alloc_decision_consistency`) so the two can never drift.
- **`allocation_targets`** — one row per target; `budget_id` NULL until approval materializes it
  into a real `budget_definitions` row; FK-scoped to `(allocation_id, tenant_id)` so a row can
  never reference another tenant's allocation (mirrors D-006's `kill_switch_outbox` FK shape).
- **`change_history`** — append-only lifecycle log (`requested`/`approved`/`rejected`), `delta_app`
  granted SELECT+INSERT only (no UPDATE, no DELETE — immutable at the grant layer, not just by
  convention).

All three: RLS `ENABLE + FORCE`, the identical strict fail-closed NULLIF predicate as
D-003/D-005/D-006.

## 4. Tenant isolation

Every route resolves `get_tenant_session(tenant_id)` for the tenant the caller explicitly
supplies; RLS is enforced by the `delta_app` (NOBYPASSRLS) role regardless of the admin bearer's
scope — the admin credential authenticates the operator, it does not carry cross-tenant data
access on its own (defense in depth, mirrors Sentinel F-012a's separation between authentication
and per-target scoping).

## 5. Threat model (vectors -> tests)

| # | Vector | Mitigation | Test |
|---|---|---|---|
| 1 | Cross-tenant allocation/history read | RLS FORCE + NULLIF predicate on all 3 tables | `test_cross_tenant_allocation_is_invisible` |
| 2 | Unreconciled allocation silently accepted (targets don't sum to total) | Validated via the shared, proven `delta.allocation.Allocation` model before any write; 422 on mismatch | `test_unreconciled_targets_rejected`, `test_unreconciled_allocation_is_422` |
| 3 | Double-decision race materializes budgets twice / overwrites a decision | Conditional `UPDATE ... WHERE status='requested'`; loser gets 409, no side effects | `test_double_decision_conflicts`, HTTP replay in `test_propose_approve_history_over_http` |
| 4 | Propose silently creates a live budget cap (no real approval gate) | `create_budget` is called ONLY from the approve branch of `decide_allocation`, never from `create_allocation_request` | `test_propose_then_approve_materializes_budgets` asserts zero `budget_id`s pre-decision; `test_reject_materializes_no_budgets` asserts zero `budget_definitions` rows after a reject |
| 5 | Missing/wrong admin bearer reaches a tenant-scoped route | `require_admin` fail-closed 401 before any `get_tenant_session` call | `test_missing_bearer_is_401`, `test_wrong_bearer_is_401` |
| 6 | Post-commit read of the just-written row bypasses RLS's transaction-local GUC and silently returns stale/empty data | `decide_allocation` builds its return value from the in-memory decision it just made — it does NOT re-query after `session.commit()` (the tenant GUC is `is_local=true` and clears on commit; a naive re-query would see zero rows under RLS, not a bug to paper over with a second session) | `test_propose_then_approve_materializes_budgets` (targets carry `budget_id` in the returned view without a second query) |
| 7 | Change-history entry tampered/deleted after the fact | `delta_app` has no UPDATE/DELETE grant on `change_history` at the database layer | (grant asserted by migration; full tamper-evidence is D-009, see fork 5) |

## 6. Honesty boundary (what D-007 is NOT)

- **Not** a tamper-evident audit trail — `change_history` is append-only-by-grant but not
  hash-chained; that guarantee is D-009, ecosystem-wide (fork 5).
- **Not** a multi-operator identity/attribution system — `requested_by`/`actor`/`decided_by` are
  free-text fields supplied by the caller, not verified against an authenticated operator
  registry (fork 3). A single break-glass bearer authorizes ANY caller who holds it to act as any
  named actor; the real-identity gap this leaves is the same one Sentinel closed for its own admin
  console via SSO (ADR-0017) — a comparable tier for Delta is a natural follow-on once Delta has
  its own operator-identity story, not built here.
- **Not** wired into `docker compose up` — see fork 9; full deployment wiring is D-010.
- **Not** a general-purpose approval-workflow engine — the state machine is specific to
  allocations (fork 2); a reusable approval entity for other Delta workflows (e.g. a future
  budget-raise approval) is a possible later generalization, not built speculatively here.
- **Not** a departmental org-hierarchy UI — "team"/"project" pickers are literally Sentinel
  `team_id`/`project_id` values the operator must already know (ADR-0001 fork 1a: no Delta-native
  org tree). A friendlier picker needs a directory Delta doesn't have yet.

## 7. Consequences

- **Positive:** turns D-005's internal-only budget-seeding path into a real, auditable,
  two-person-rule-capable admin workflow with zero new budget-creation code (reuses `create_budget`
  unchanged); the change-history log gives D-009 a ready-made table to extend with a hash chain
  rather than retrofitting one from nothing.
- **Negative / accepted:** single break-glass auth means no per-operator attribution beyond
  free-text fields (§6); no docker-compose service (§6, deferred to D-010); the frontend's
  team/project/agent pickers are raw UUID/slug text inputs, not a searchable directory (no
  directory service exists yet to back one).
