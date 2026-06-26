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

## Layout

```
src/delta/        Pydantic v2 domain types + validators (the invariants)
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
