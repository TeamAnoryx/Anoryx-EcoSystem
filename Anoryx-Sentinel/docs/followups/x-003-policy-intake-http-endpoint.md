# Follow-up: Sentinel needs a real policy-intake HTTP endpoint for X-003

**Status:** OPEN — blocked on `contracts/` access (api-architect only) AND a
security-relevant reversal of an explicit prior decision (ADR-0009 §11, R1).
**Severity:** None yet (no live vulnerability — the gap is that the loop
cannot close at all today, not that it closes insecurely).
**Owner:** api-architect (contracts/openapi.yaml) + human sign-off (this
reverses a deliberate attack-surface-reduction call, not an oversight).

## What X-003 needs

X-003 ("Budget enforcement loop — the killer feature") requires a
non-stubbed, three-hop end-to-end proof: Delta's budget engine (D-005) hits a
cap → Orchestrator's policy-distribution engine (O-004) distributes the deny
policy → **Sentinel's F-008 intake accepts it over the wire and the very next
request from that scope is blocked** — all within ~1 second.

## What's actually shipped, hop by hop

1. **Delta D-005** (`Delta/src/delta/budget_engine/evaluator.py` +
   `drainer.py`) — real. On cap breach it queues a signed-outbox row and the
   drainer signs + `POST`s it to Orchestrator's
   `/v1/policies/distributions`.
2. **Orchestrator O-004**
   (`Anoryx-AI-Orchestrator/src/orchestrator/distribution/engine.py`) — real.
   `drive_distribution()` forwards the byte-identical signed record via
   `httpx` to `settings.targets[sentinel_id] + settings.intake_path`
   (default path `/admin/policies/intake`, env `ORCH_SENTINEL_INTAKE_PATH`),
   with `Authorization: Bearer <SENTINEL_ADMIN_TOKEN>`. This is genuinely
   implemented and already merged — but its own test suite
   (`test_o004_e2e.py`, `test_distribution_e2e.py`) only ever points
   `settings.targets` at a trivial in-test accepting shim, never at real
   Sentinel code.
3. **Sentinel F-008** (`Anoryx-Sentinel/src/policy/intake.py`) — real,
   fully-implemented, fail-closed `intake_policy()` pipeline. But
   **ADR-0009 §11 explicitly decided "internal-only (no new HTTP
   endpoint — R1)"**: the only caller is `sentinel-cli policy push`. No later
   feature added an HTTP route for it — F-012a's admin API adds only a
   **read-only** `GET /admin/tenants/{tenant_id}/policies`
   (`contracts/openapi.yaml:1013`, "no policy is \[written]" per its own
   description).

## Net effect

Every individual piece is real, shipped, and (for F-008) independently
security-audited. But there is no route mounted anywhere in Sentinel at
`/admin/policies/intake` (or any other path) that O-004 could actually reach.
In a real deployment, Orchestrator's distribution attempt would get a **404**
on every target — the budget-enforcement loop cannot close end-to-end today,
even though it looks wired from the code on both sides.

## Why a builder agent should not just add the endpoint

Closing this gap for real means adding a new authenticated HTTP surface to
Sentinel — `POST /admin/policies/intake` (the path O-004 already assumes by
default) — which:

1. Requires editing `contracts/openapi.yaml`, locked to the api-architect
   agent (hook-enforced for everyone else).
2. Directly reverses ADR-0009 §11's R1 decision, which was a deliberate
   attack-surface reduction on a zero-trust security product ("internal-only,
   no HTTP" — not an oversight). Whether to reverse it, and under what
   authentication/threat-model constraints, is a human/api-architect call,
   not something a builder should force through unilaterally.

This followup intentionally stops short of implementing anything.

## Proposed shape (for whoever picks this up)

- `POST /admin/policies/intake` under the existing `/admin/*` surface,
  authenticated the same way as the rest of F-012a's admin API
  (`SENTINEL_ADMIN_TOKEN`-bearing principal — the same bearer O-004 already
  sends).
- Request body: the signed policy record, byte-identical to what
  `sentinel-cli policy push` already sends into `intake_policy()` — no new
  shape.
- Response: map the existing `IntakeResult` variants
  (`Accepted | RejectedSchema | RejectedSignature | RejectedScopeMismatch |
  RejectedReplay`) to HTTP statuses in the OpenAPI spec itself (api-architect
  chooses the exact codes) rather than inventing ad hoc per-caller codes.
- Implementation should be a thin wrapper only: the route calls the existing
  `intake_policy()` directly and adds no new business logic or bypass of its
  fail-closed pipeline.
- Needs a short ADR addendum reconciling ADR-0009 R1 plus a threat-model note
  (who can reach the route; replay/rollback is already handled inside
  `intake_policy()`) before merging — this is a brand-new ingress path into a
  security product's policy store.

## What happens after the endpoint lands

Once api-architect adds the endpoint (+ ADR addendum), X-003's actual
deliverable — the non-stubbed three-hop e2e test proving cap-breach →
distribute → real-intake → real-enforcement within ~1s — is a normal builder
task (orchestration-hooks or policy-engine), replacing the shim targets in
`test_o004_e2e.py` / `test_distribution_e2e.py` with the real Sentinel route.
