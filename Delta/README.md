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

## Layout

```
src/delta/        Pydantic v2 domain types + validators (the invariants)
src/delta/persistence/audit_log.py  D-009 hash-chained audit log (append_history/list_history/verify_chain)
src/delta/allocation_admin/  D-007 budget-allocation admin API (propose/approve/reject, history)
src/delta/dashboards/        D-008 read-only spend aggregates (summary, time series, top spenders)
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
