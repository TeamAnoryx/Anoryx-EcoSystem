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
plain (not hash-chained — that's D-009) change-history log. See
[`docs/adr/0007-delta-budget-allocation-ui.md`](docs/adr/0007-delta-budget-allocation-ui.md).

- **Backend:** `src/delta/allocation_admin/` — a FastAPI admin app (`/v1/admin/*`), separate
  from the D-004 ingest app. Single break-glass bearer auth (`DELTA_ADMIN_TOKEN`, mirrors
  Sentinel F-012a). Run it with `uvicorn "delta.allocation_admin.app:create_app" --factory`.
- **Frontend:** `frontend/` — a Next.js admin console, BFF-only (mirrors
  `Anoryx-Sentinel/frontend/`: the browser only ever holds a signed session cookie, never the
  bearer token). See [`frontend/README.md`](frontend/README.md).
- **Not** wired into `docker-compose.yml` — no Delta HTTP app is (D-004's ingest app and
  D-005/D-006's engines ship the same way); full service wiring is D-010 (Deployment).

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

## Layout

```
src/delta/        Pydantic v2 domain types + validators (the invariants)
src/delta/allocation_admin/  D-007 budget-allocation admin API (propose/approve/reject, history)
src/delta/dashboards/        D-008 read-only spend aggregates (summary, time series, top spenders)
frontend/         D-007/D-008 Next.js admin console (BFF-only, see frontend/README.md)
contracts/        Delta-owned JSON Schemas (Draft 2020-12, additionalProperties:false)
tests/            non-stubbed proofs of every invariant + the Budget round-trip
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
