# Delta

FinOps / ERP / budget-policy product in the Anoryx EcoSystem.

> Ecosystem data flow:
> `Sentinel → (usage/cost events) → Anoryx-AI-Orchestrator → Delta`
> `Delta → (budget policies) → Anoryx-AI-Orchestrator → (enforcement) → Sentinel`
> The killer feature is financial policy enforced in the security path.

## D-001 — Financial Domain Model (this task)

D-001 ships the **canonical financial vocabulary and its integrity invariants
only**: accounts, ledger entries, transactions, cost centers, projects,
allocations, budget concepts, usage records, time windows, and burn-rate — as
Pydantic v2 types + JSON Schemas + real validators. See
[`docs/adr/0001-delta-financial-domain-model.md`](docs/adr/0001-delta-financial-domain-model.md).

D-001 is explicitly **not**:

- the ledger engine (D-003),
- the budget engine (D-005),
- any DDL / database migration (DDL is D-003's authority — none is shipped here).

### Locked decisions (ADR-0001)

- **Attribution** — a cost center *is* a Sentinel `team_id`; every cost is
  attributed to the four Sentinel stable IDs `(tenant_id, team_id, project_id,
  agent_id)` exactly as they arrive on events. No org hierarchy yet.
- **Money** — integer minor units (**cents**); **floats are forbidden** in every
  monetary field; values bounded to the wire maxima.
- **Cost source** — Delta *records* the cost Sentinel computed
  (`UsageEvent.cost_estimate_cents`); no Delta pricing table. Figures are
  *client-side cost estimates*, never authoritative bills.
- **Currency** — single currency, ISO-4217 tagged (default `USD`), no FX;
  mixing currencies in a netted set is rejected.
- **Schema authority** — types + JSON Schemas here; authoritative ledger DDL is
  deferred to D-003. Types are shaped tenant-first so D-003 applies the F-003b
  RLS pattern with no reshape.

### Honesty boundary

D-001 ships the model and its invariants only. It does not enforce a budget, post
to a ledger, or bill anyone — enforcement lives in D-003 / D-005.

### Budget-variant compatibility

`BudgetConcept` maps 1:1 onto Sentinel's **LOCKED** `BudgetLimitPolicy`
(`Anoryx-Sentinel/contracts/policy.schema.json`, frozen at F-008 `a9e2344`) with
no schema change. Proven by `tests/test_budget_variant_roundtrip.py`, which
validates a Delta-emitted `budget_limit` record against that locked schema.

## D-007 — Budget Allocation Admin (API + console)

D-007 turns D-005's internal-only `budget_engine.definitions.create_budget` seam into an
authenticated, auditable admin workflow: propose an allocation (a tenant total distributed
across scope targets) -> an explicit approve/reject decision -> approve materializes each
target into a real budget cap, reject has no side effect. Every transition is appended to a
change-history log (hash-chained by D-009). See
[`docs/adr/0007-delta-budget-allocation-ui.md`](docs/adr/0007-delta-budget-allocation-ui.md).

- **Backend:** `src/delta/allocation_admin/` — a FastAPI admin app (`/v1/admin/*`), separate
  from the D-004 ingest app. Single break-glass bearer auth (`DELTA_ADMIN_TOKEN`, mirrors
  Sentinel F-012a). Run it with `uvicorn "delta.allocation_admin.app:create_app" --factory`.
- **Frontend:** `frontend/` — a Next.js admin console, BFF-only (mirrors
  `Anoryx-Sentinel/frontend/`: the browser only ever holds a signed session cookie, never the
  bearer token). See [`frontend/README.md`](frontend/README.md).
- Wired into `docker-compose.yml` as the `delta-admin` service as of D-010 (Deployment).

## D-008 — Live Cost-to-Value Dashboards

D-008 adds read-only spend aggregates (real-time total, burn rate, time series, top spenders,
cost-per-request) over the D-003 ledger, parametrized by tenant + optional team/project/agent
scope + time window. Zero new migration (pure `SELECT`/`GROUP BY` over the existing
`ledger_entries`); mounted into the same admin app D-007 built (`allocation_admin/app.py`) rather
than a second process. See
[`docs/adr/0008-delta-cost-dashboards.md`](docs/adr/0008-delta-cost-dashboards.md).

- **Backend:** `src/delta/dashboards/` — `GET /v1/admin/dashboards/{summary,timeseries,
  top-spenders}`, same auth/app/console as D-007.
- **Frontend:** `frontend/(admin)/dashboards` — stat tiles, an SVG spend-over-time chart, a
  ranked top-spenders list, and a plain data table. Now the console's landing page.
- **Honesty boundary:** "cost-per-outcome" (the roadmap's phrasing) is not built — Delta has no
  "outcome" domain concept to divide cost by. Only cost-per-*request* is exposed.

## D-009 — Immutable Financial-Workflow Audit Trails

D-009 upgrades D-007's plain `change_history` log into a hash-chained, tamper-evident audit trail
— the Sentinel F-003 pattern applied to Delta's financial actions, with a deliberate divergence:
Delta's chains are **per-tenant** (not Sentinel's global chain), so an audit append happens in the
SAME transaction as the business write it records — a financial write and its audit row can never
diverge. Every automated financial workflow the roadmap names is wired in: allocation lifecycle
(D-007), budget-engine enforcement decisions (D-005), kill-switch kill/clear decisions (D-006), and
allocation-reconciliation failures. See
[`docs/adr/0009-delta-financial-audit-chain.md`](docs/adr/0009-delta-financial-audit-chain.md).

- **Core module:** `src/delta/persistence/audit_log.py` — `append_history` (hash + insert, caller's
  transaction), `list_history`, `verify_chain` (walks a tenant's chain, recomputes every hash,
  reports the first tamper if any).
- **Migration:** `0006_audit_hash_chain.py` — upgrades `change_history` in place (adds
  `sequence_number`/`prev_hash`/`row_hash`, backfills deterministically, locks down with
  constraints + append-only triggers reusing D-003's `deny_ledger_modification()`).
- **New endpoint:** `GET /v1/admin/audit/verify?tenant_id=...` on the same D-007 admin app —
  returns `{is_valid, rows_checked, first_mismatch_sequence, error_detail}`.
- **Append-only, two layers:** `delta_app` has no UPDATE/DELETE grant on `change_history` (grant
  layer); a trigger denies modification regardless of role (privileged-role layer, since triggers —
  unlike RLS — aren't skipped by `BYPASSRLS`).
- **Honesty boundary:** a hash chain proves internal consistency and catches tampering of EXISTING
  rows; it does not prove the chain wasn't entirely regenerated by someone with full database
  access (no external anchoring is built — same limitation Sentinel's own F-003 has). Not
  encrypted at rest beyond the deployment's own Postgres-level encryption (no envelope encryption,
  mirroring Sentinel's audit table). `verify_chain` is pull-based, not push-alerted.

## D-010 — Deployment (Docker + Helm + K8s-native secrets)

D-010 packages the two Delta ASGI apps (`delta.ingest.app` — the runtime enforcement hot path, and
`delta.allocation_admin.app` — the internal operator console) plus a bundled Postgres into a
`docker compose` stack and a Helm chart, mirroring the pattern Anoryx-Sentinel's F-010 and
Anoryx-AI-Orchestrator's O-008 already established. Zero application code changed — both apps and
their `/health` endpoints already existed; this task is pure packaging. See
[`docs/adr/0010-delta-deployment.md`](docs/adr/0010-delta-deployment.md) and
[`deploy/DEPLOY-K8s.md`](deploy/DEPLOY-K8s.md).

- **Docker:** `Dockerfile` — multi-stage, non-root (uid 1000), no baked secrets, one image serving
  both apps via an explicit `command` per service. `docker-entrypoint.sh` bridges file-based
  Docker secrets (`/run/secrets/*`) or Kubernetes `Secret`/env to the app's config, runs migrations,
  and provisions the `delta_app` SCRAM password (unchanged from D-003/D-009).
- **Compose:** `docker-compose.yml` — `postgres` + `delta-migrate` (existing) plus two new services,
  `delta-ingest` (port 8000) and `delta-admin` (port 8001), both gated on `delta-migrate` completing
  successfully. Secrets are file-based throughout (`deploy/secrets/gen-dev-secrets.sh` generates
  dev-only values; never commit real credentials).
- **Helm:** `deploy/helm/delta/` — two Deployments/Services/NetworkPolicies/PDBs (`ingest`, `admin`),
  a bundled-Postgres subchart-style set of templates (`postgres.bundled=true` default, `.external`
  escape hatch), and a migration Job gated by `wait-for-postgres`/`wait-for-migrate` init containers.
  The admin console's NetworkPolicy is same-namespace + monitoring-namespace ingress ONLY — no
  open-by-default external rule, unlike the ingest component (which, like Sentinel's and the
  Orchestrator's own ingest seams, cannot know its external callers' addresses at chart-render time).
- **Honesty boundary:** real Vault/KMS integration and real mTLS between Delta and the Orchestrator's
  O-004 distribution seam are explicitly, honestly deferred — there is no reference implementation
  for either anywhere in this repository yet (same deferral Sentinel's F-010 and the Orchestrator's
  O-008 both made). The interim peer authenticator is the existing `ORCH_SERVICE_TOKEN` bearer. No
  Redis is bundled — zero Delta code imports it; the roadmap's generic "Postgres + Redis" phrasing is
  not a reviewed dependency list.

## D-011 — Predictive Budget Forecasting

D-011 projects a budget period's end-of-period spend by holding the CURRENT elapsed-period average
rate constant (the exact "flat average" concept D-008's `burn_rate_cents_per_hour` already uses,
extended to project forward) and returns deterministic, threshold-based advisory recommendations.
Deliberately **not** a regression or trained/validated statistical model — no forecasting precedent
exists anywhere in this ecosystem to build one against. See
[`docs/adr/0011-delta-budget-forecasting.md`](docs/adr/0011-delta-budget-forecasting.md).

- **Backend:** `src/delta/forecasting/` — `projection.py` (pure current-rate projection +
  first-half/second-half trend direction, no I/O), `recommendations.py` (deterministic advisory
  text reusing D-005's `decision.is_over_cost_cap`/`soft_warning_band`), `service.py`
  (orchestration — every spend figure comes from `budget_engine.spend.scope_spend_cents`, the SAME
  query enforcement itself uses).
- **New endpoint:** `GET /v1/admin/forecast/budgets[/{budget_id}]` on the same D-007 admin app —
  returns current-period spend, burn rate, projected period-end spend, projected exhaustion date
  (if any), trend direction, and a list of recommendations (`INSUFFICIENT_DATA`, `NO_COST_CAP`,
  `ALREADY_OVER_CAP`, `SOFT_THRESHOLD_CROSSED`, `PROJECTED_TO_EXCEED`, `RISING_TREND`,
  `SPEND_CONCENTRATION`).
- **Zero new migration** — every forecast is computed live from `budget_definitions` (D-005) +
  `ledger_entries` (D-003); nothing is persisted or historized.
- **Honesty boundary:** `method: "current_rate_projection_v1"` is always returned — a literal,
  versioned tag naming the technique honestly. The projection is a `float` estimate, never fed back
  into an actual enforcement decision (those stay strictly integer, `budget_engine.decision`'s own
  invariant, unchanged). No forecast-accuracy tracking is built (nothing persists a prediction to
  later compare against reality) — real, valuable future work this task does not claim to deliver.

## D-012 — Chargeback / Showback + Anomaly Detection

D-012 attributes cost to a department (team/project/agent) over a window — a chargeback/showback
report, informational only, never an authoritative bill — and flags groups whose current spend
looks unusual relative to their own trailing baseline average. Anomaly detection is a fixed-multiple
ratio comparison (`current window spend / trailing N-period average`), deliberately **not** a
z-score/stddev or trained/validated statistical/ML model — same "no ecosystem precedent to build one
against" reasoning D-011's ADR already established. See
[`docs/adr/0012-delta-chargeback-anomaly-detection.md`](docs/adr/0012-delta-chargeback-anomaly-detection.md).

- **Backend:** `src/delta/chargeback/` — `anomaly.py` (pure trailing-average-ratio detection, no
  I/O), `schemas.py` (`ChargebackQuery`/`AnomalyQuery`, bounded window + bounded total baseline
  span), `service.py` (orchestration — reuses D-008's `dashboards.store.top_spenders` unchanged;
  exactly 2 DB queries total for an anomaly report, never one per group).
- **New endpoints:** `GET /v1/admin/chargeback/report` (spend + `share_pct` per group) and
  `GET /v1/admin/chargeback/anomalies` (`SPEND_SPIKE`/`NEW_SPENDER` flags, `method:
  "trailing_average_ratio_v1"`) on the same D-007 admin app.
- **Frontend:** `/chargeback` page — filter form (tenant, window, baseline periods, optional
  team/project/agent scope), stat tiles (total spend, departments, anomalies flagged), a chargeback
  report table, and an anomalies table with a severity-colored signal badge.
- **Zero new migration** — every report is computed live from `ledger_entries` (D-003) via
  `top_spenders`; nothing is persisted or historized.
- **Honesty boundary:** `method: "trailing_average_ratio_v1"` is always returned — a literal,
  versioned tag naming the technique honestly, mirroring D-011's `method` field. Chargeback figures
  are the same client-side cost estimates the rest of Delta already is — informational
  cost-attribution, never a real invoice (Delta has no billing/AR system). Only groups with cost
  OVERRUNS are flagged (no underspend/`SPEND_DROP` signal) and no anomaly-acknowledgment workflow
  exists — both named as real, deferred future work, not silently omitted.

## D-013 — Unified CRM (🏦 post-investment vision tier)

D-013 is the first task built past Delta's committed MVP (D-001→D-012, all shipped) into the
`🏦 POST-INVESTMENT` vision tier — greenlit explicitly, not assumed. It is a deliberately bounded
vertical slice of the roadmap's "complete enterprise deal pipeline... relationship scoring,
automated stakeholder mapping," not full enterprise-CRM feature parity: client records, a deal
pipeline, a stakeholder roster, an interaction history, and a deterministic relationship-score
heuristic. See [`docs/adr/0013-delta-unified-crm.md`](docs/adr/0013-delta-unified-crm.md).

- **Backend:** `src/delta/crm/` — `scoring.py` (pure recency + frequency relationship-score
  heuristic, no I/O), `schemas.py` (client/deal/stakeholder/interaction DTOs, bounded free text,
  `require_aware_utc` timestamps), `store.py` (SQLAlchemy Core persistence — stakeholder engagement
  and relationship-score inputs are O(1) aggregate queries, never one-per-row), `service.py`
  (orchestration — an explicit client-scope check above the tenant-scoped composite FKs, since an FK
  alone proves same-TENANT, not same-CLIENT).
- **New tables** (migration 0007): `clients`, `deals`, `stakeholders`, `interactions` — every FK is a
  composite `(entity_id, tenant_id)` pair (mirrors D-007's `allocation_targets` pattern), same
  fail-closed RLS predicate as every prior Delta migration. `interactions` is INSERT/SELECT-only at
  the grant layer (an interaction log entry, once written, is never edited).
- **New endpoints:** `GET/POST /v1/admin/crm/clients[/{id}]`, `.../deals`,
  `POST /v1/admin/crm/deals/{id}/stage`, `.../stakeholders`, `.../interactions`,
  `GET .../relationship-score` — all on the same D-007 admin app, same `require_admin` auth.
- **Frontend:** `/crm` (client list + create form) and `/crm/{clientId}` (deal pipeline with an
  inline stage-transition control, stakeholder roster with live-computed engagement, interaction
  timeline, relationship-score stat tiles) via Server Actions (mirrors `allocations/actions.ts`).
- **Honesty boundary:** `method: "recency_frequency_v1"` is always returned — a deterministic,
  explainable heuristic, **not** a trained/validated statistical or ML model (same "no ecosystem
  precedent" reasoning as D-011/D-012). Stakeholder "automated" mapping means engagement
  (interaction_count/last_interaction_at) is computed live from explicit interaction tags, never
  NLP-extracted from free text. A deal's `value_minor_units` is CRM-local pipeline data, never fed
  into any ledger/budget/forecast figure — Delta still has no billing/AR system. Not wired into
  D-009's hash-chained audit log (that chain is scoped to automated FINANCIAL workflows; CRM edits
  are business-process data) — named as a deliberate scope boundary, not an oversight.

## D-014 — ERP: Asset Register + Vendor/Purchase-Order Procurement (🏦 post-investment vision tier)

D-014 is the second task built past Delta's committed MVP into the vision tier, continuing
directly from D-013 per explicit instruction to keep going. A deliberately bounded slice of the
roadmap's "real-time sync of supply chain, payroll, HR, and physical assets — the full ERP": an
asset register and a vendor/purchase-order procurement workflow. **No payroll, no HR, no external
real-time sync** (that's D-019's explicitly-dependent future task). See
[`docs/adr/0014-delta-erp-assets-procurement.md`](docs/adr/0014-delta-erp-assets-procurement.md).

- **Backend:** `src/delta/erp/` — `schemas.py` (vendor/asset/PO DTOs, the same value/currency
  pairing discipline D-013's audit caught, applied here proactively from the start), `store.py`
  (SQLAlchemy Core persistence — forward-only asset lifecycle via a conditional
  `UPDATE ... WHERE status = required_prior`, same race-guard shape as D-007's allocation decisions
  and D-013's deal-stage transitions), `service.py` (orchestration — a PO decision writes into
  D-009's hash-chained audit log in the SAME transaction as the status change, since a purchase
  order IS a financial commitment, unlike D-013's CRM edits).
- **New tables** (migration 0008): `vendors`, `assets`, `purchase_orders` — every FK is a composite
  `(entity_id, tenant_id)` pair, same fail-closed RLS predicate as every prior Delta migration, no
  DELETE grants anywhere.
- **New endpoints:** `GET/POST /v1/admin/erp/vendors`, `.../assets`, `POST .../assets/{id}/status`,
  `.../purchase-orders`, `POST .../purchase-orders/{id}/decision` — all on the same D-007 admin app,
  same `require_admin` auth.
- **Frontend:** `/erp` — vendor directory, asset register with an inline lifecycle-transition
  control, and a purchase-order list with inline approve/reject decisions, via Server Actions.
- **Honesty boundary:** a purchase order's amount is a procurement commitment an operator enters,
  never validated against a real payment or contract — Delta still has no billing/AR/payments
  system. No depreciation schedule, no multi-line PO items, no receiving/fulfillment tracking (that
  overlaps D-018's separate scope). Asset lifecycle is forward-only (active → retired → disposed)
  by design — enforced at the query layer like D-013's deal stages, not a closed DB vocabulary.

## D-015 — Project Management: Sprints, Tasks, Dependency Mapping (🏦 post-investment vision tier)

D-015 is the third task built past Delta's committed MVP into the vision tier, continuing
directly from D-014 per explicit instruction to keep going. A deliberately bounded slice of the
roadmap's "sprint-velocity tracking, dependency mapping, execution-bottleneck prediction —
real-time": sprints, tasks, a real dependency graph with cycle rejection, a sprint-velocity
report, and a deterministic blocking-fan-out bottleneck heuristic. **No real-time push updates,
no external issue-tracker integration, no trained/validated ML prediction.** See
[`docs/adr/0015-delta-pm-sprints-dependencies.md`](docs/adr/0015-delta-pm-sprints-dependencies.md).

- **Backend:** `src/delta/pm/` — `schemas.py` (sprint/task/dependency DTOs, `reject_non_integer`
  on `story_points` applied proactively from the start), `store.py` (SQLAlchemy Core persistence —
  the velocity and bottleneck reports are each ONE bounded aggregate SQL query, never a per-row
  Python loop), `service.py` (orchestration — `_would_create_cycle` is a bounded BFS over the
  tenant's dependency edges, run before every new edge is inserted; a genuinely novel piece of
  logic with no precedent in D-007→D-014).
- **New tables** (migration 0009): `sprints`, `tasks`, `task_dependencies` — every FK is a
  composite `(entity_id, tenant_id)` pair, same fail-closed RLS predicate as every prior Delta
  migration. `task_dependencies` is INSERT/SELECT-only at the grant layer (an edge, once created,
  is never edited — mirrors D-013's `interactions` append-only pattern).
- **New endpoints:** `GET/POST /v1/admin/pm/sprints`, `POST .../sprints/{id}/status`,
  `GET/POST .../tasks`, `POST .../tasks/{id}/status`, `POST .../dependencies`,
  `GET .../tasks/{id}/dependencies`, `GET .../velocity`, `GET .../bottlenecks` — all on the same
  D-007 admin app, same `require_admin` auth.
- **Frontend:** `/pm` — sprint list with a status select, task list with a status select, a
  task-dependency linker, a sprint-velocity table, and a bottleneck-report table, via Server
  Actions.
- **Honesty boundary:** `method: "blocking_fanout_v1"` is always returned on the bottleneck
  report — a deterministic, explainable ranking by direct blocking count, **not** a trained/
  validated statistical or ML prediction model (same "no ecosystem precedent" reasoning as
  D-011/D-012/D-013). Task status is deliberately reopenable (todo/in_progress/blocked/done) —
  unlike D-013's deal stages or D-014's asset lifecycle, there is no forward-only invariant here.
  Not wired into D-009's hash-chained audit log (task/sprint edits are business-process data, not
  financial transactions — mirrors D-013's CRM boundary). No real-time push updates, no external
  issue-tracker sync (Jira/Linear/GitHub Issues) — named as unclaimed future work, not
  approximated.

## Layout

```
src/delta/        Pydantic v2 domain types + validators (the invariants)
src/delta/persistence/audit_log.py  D-009 hash-chained audit log (append_history/list_history/verify_chain)
src/delta/allocation_admin/  D-007 budget-allocation admin API (propose/approve/reject, history)
src/delta/dashboards/        D-008 read-only spend aggregates (summary, time series, top spenders)
src/delta/forecasting/       D-011 current-rate budget-forecast projection + advisory recommendations
src/delta/chargeback/        D-012 departmental chargeback/showback + trailing-average anomaly detection
src/delta/crm/                D-013 unified CRM (deal pipeline, stakeholders, interactions, relationship score)
src/delta/erp/                D-014 asset register + vendor/purchase-order procurement
src/delta/pm/                 D-015 sprints, tasks, dependency mapping, velocity + bottleneck reports
frontend/         D-007/D-008 Next.js admin console (BFF-only, see frontend/README.md)
contracts/        Delta-owned JSON Schemas (Draft 2020-12, additionalProperties:false)
tests/            non-stubbed proofs of every invariant + the Budget round-trip
deploy/           D-010 Helm chart (deploy/helm/delta) + K8s deploy guide + dev-secret generators
docs/adr/         Delta architecture decision records
docs/audit/       security audit records
```

## Develop

```bash
pip install -e ".[dev]"
python -m pytest -q --cov=src --cov-report=term-missing
ruff check . && black --check .
```

Allocation-admin API (D-007), against a migrated DB (see `alembic upgrade head` above):

```bash
export DELTA_ADMIN_TOKEN=<a-local-dev-token>
uvicorn "delta.allocation_admin.app:create_app" --factory --port 8010
```

Frontend console (D-007) — see [`frontend/README.md`](frontend/README.md) for the full env list:

```bash
cd frontend && npm install && npm run dev
```
