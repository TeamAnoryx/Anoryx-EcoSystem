# ADR-0014 — Fleet Command-Center Summary + Guarded, Operator-Triggered Distribution Rollback

- Status: Accepted
- Date: 2026-07-08
- Task: O-014 (fourteenth Orchestrator task, second task from the roadmap's Phase 2
  ecosystem-integration tier)
- Builds on: ADR-0004 (O-004 distribution engine — the persist/audit/dispatch pipeline
  this reuses verbatim for the rollback action), ADR-0005 (O-005 registry health), ADR-0007
  (O-007 admin API — the `_require_admin` operator-bearer boundary this reuses), ADR-0013
  (O-013 external gateway — the newest precedent for a per-router `_require_admin` copy
  and a fixed-window/aggregation read)
- Supersedes: nothing. Adds one new package (`command_center`), one new table
  (`distribution_rollbacks`), one new hash chain, and a standalone
  `CommandCenterSettings`; does not alter any existing seam, engine, schema, or credential.

This run's default posture is to stop in front of the 🏦 POST-INVESTMENT gate; the task
owner has explicitly authorized proceeding with post-investment tasks in this run — the
same standing authorization already recorded in ADR-0009→ADR-0013.

## Context

The roadmap lists O-014 as **"Command dashboard + automated rollback. Comprehensive
command center (system health, API loads, governance metrics across all products) +
automated rollback if the orchestration loop detects a critical system failure."** This is
not buildable as a single, honest PR today, for two independent reasons:

- **"Comprehensive command center... across all products" implies cross-product
  telemetry the Orchestrator does not have.** Delta and Rendly do not push API-load or
  governance metrics into the Orchestrator — the only cross-product signal that reaches
  this codebase is what already flows through the O-003 ingest seam (tagged
  `source_product` events) and the O-013 external gateway. There is no shared metrics
  pipeline to aggregate, and building one would mean reaching into Delta/Rendly's own
  internals, which this repo's protect-paths hook forbids for `Anoryx-AI-Orchestrator/`
  code.
- **"Automated rollback if the orchestration loop detects a critical system failure" names
  an autonomous capability with no defined trigger anywhere in this codebase.** There is
  no "critical system failure" detector, no agreed failure taxonomy, and no generic
  "rollback" primitive that applies uniformly across the Orchestrator's disparate
  subsystems (registry entries, policy distributions, automation rules, external-gateway
  keys). Building an autonomous system that can revert arbitrary state on its own
  judgment — with no human in the loop and no established definition of what "critical"
  means — is a genuinely dangerous, ill-defined undertaking; ADR-0011's caution about new
  autonomous side effects applies here with MORE force, not less, because a mistaken
  autonomous rollback of a policy distribution has real security-enforcement consequences
  (see F-008/F-016's own CRIT-2 lessons on what happens when enforcement logic ships
  inert or wrong).

This ADR resolves that tension the same way ADR-0009→ADR-0013 resolved their own literal
roadmap text: ship the smallest genuinely useful, honest slice — a read-only fleet-health
summary over metrics the Orchestrator ALREADY collects, plus ONE well-defined,
OPERATOR-TRIGGERED "rollback" primitive built entirely on the EXISTING O-004 distribution
engine — and name everything else (cross-product telemetry, autonomous failure detection,
a generic rollback-anything mechanism) as an honest, explicit deferral.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — what "comprehensive command center... across all products" means without a cross-product telemetry pipeline | **A1**: `GET /v1/admin/command-center/summary` aggregates ONLY what the Orchestrator's own tables already track: multi-Sentinel registry health (O-005), policy-distribution outcomes over a bounded lookback window (O-004), automation-rule execution outcomes (O-011), external-gateway access attempts (O-013), and raw ingest event throughput (O-003). Cross-tenant by design (operator fleet triage, mirrors `admin/router.py`'s O-007 reads exactly). |
| **B** — what "automated rollback... if the orchestration loop detects a critical system failure" means without an autonomous failure detector | **B1**: `POST /v1/admin/policy-distributions/rollback` is a single, well-defined, OPERATOR-TRIGGERED action — re-submit the IMMEDIATELY PRIOR signed policy record for a given `(tenant_id, policy_id)` pair. There is no autonomous trigger, no failure-detection heuristic, and no generic "rollback anything" mechanism — this is the ONE concrete, safe, reversible primitive this PR builds, requiring an explicit human action authenticated by the SAME operator bearer already gating every other O-007/O-013-style admin write. |
| **C** — how the rollback identifies "the tenant" | **C1**: the operator supplies `tenant_id` explicitly in the request body — there is no implicit resolution. Unlike `GET /v1/policies/distributions/{distribution_id}` (which resolves an unknown distribution's owning tenant via a privileged pre-read because the id alone carries no tenant context), the rollback's own lookup runs directly on `get_tenant_session(tenant_id)`: the operator is already fully privileged (holds `ORCH_ADMIN_TOKEN`), so there is no privacy boundary to protect by hiding which tenant a `policy_id` belongs to, and requiring the caller to state it explicitly is simpler and avoids a silent cross-tenant `policy_id` collision resolving to the wrong tenant's row. |
| **D** — what "rollback" concretely does | **D1**: fetch the two most-recent `policy_distributions` rows for `(tenant_id, policy_id)`; if fewer than two exist, `409 nothing_to_roll_back_to` (there is no earlier version). Otherwise, byte-identically re-submit the SECOND row's `signed_record`/`content_hash`/`policy_version`/`policy_type` as a BRAND NEW distribution (fresh `distribution_id`), targeting the SAME `sentinel_id`s the prior distribution targeted (read from its own `policy_distribution_targets` rows). This reuses `insert_policy_distribution` + `insert_distribution_target` + `drive_distribution` VERBATIM — the exact same persist/audit/dispatch path an ordinary `POST /v1/policies/distributions` submission takes. No new dispatch logic exists anywhere in this PR. |
| **E** — audit shape | **E1**: the new distribution gets its OWN `distribution_audit_log` link (`disposition='submitted'`) — identical to any other distribution, because it genuinely IS another distribution submission. A SEPARATE, new `distribution_rollbacks` correlation chain additionally records the operator ACTION itself: which distribution was re-submitted (`source_distribution_id`), which distribution it superseded (`superseded_distribution_id`), and the new distribution it created (`new_distribution_id`). Two chains, two distinct facts — never conflated. |
| **F** — master enable/disable switch | **F1**: NONE. The summary is read-only (mirrors the O-007 admin reads, which have no switch). The rollback action already requires the operator bearer PLUS an explicit `(tenant_id, policy_id)` target with a real "at least two distributions exist" precondition — there is no autonomous behavior to gate, unlike O-011's automation engine (whose master switch exists specifically because a MATCHED RULE fires with no interactive caller in the loop). This mirrors ADR-0012/ADR-0013's identical "ordinary explicit-caller action, no switch needed" reasoning. |
| **G** — lookback window bound | **G1**: `ORCH_COMMAND_CENTER_LOOKBACK_HOURS` (default 24, ≥ 1) bounds every windowed COUNT in the summary (distributions/automation/external-gateway/ingest/rollbacks) — a fixed, bounded scan, never an unbounded full-table COUNT. Registry health is NOT windowed (a Sentinel's `health_status` is already the latest known point-in-time state, ADR-0005 — there is no "over a window" version of it to bound). |
| **H** — response shape stability | **H1**: the summary's four closed-enum groupings (registry `health_status`, distribution `state`, automation `disposition`, external-gateway `outcome`) are ZERO-FILLED with every known enum member before the actual COUNT results are merged in — a consumer always sees the same set of keys regardless of which outcomes happened to occur in the lookback window, rather than a shape that silently varies. |

## API additions

- `GET /v1/admin/command-center/summary` — operator-gated, cross-tenant. `200
  {generated_at, lookback_hours, registry: {unknown, healthy, degraded, unreachable},
  distributions: {pending, distributed, partial, failed}, automation_executions:
  {executed, failed}, external_gateway: {allowed, scope_denied, rate_limited, revoked},
  ingest_events_count, rollbacks_count}`.
- `POST /v1/admin/policy-distributions/rollback` — operator-gated. Body:
  `{tenant_id, policy_id}` → `202 {distribution_id, policy_id, state: "pending",
  rolled_back_to_distribution_id, superseded_distribution_id}` / `409
  nothing_to_roll_back_to` (fewer than two distributions exist for this pair).

Both reuse `operatorBearer` (the SAME scheme as O-005/O-007/O-013's admin seams).

## Data access

The summary runs every count on the PRIVILEGED session (cross-tenant fleet triage,
mirrors `admin/router.py`). The rollback action's lookup, insert, and target-copy all run
on ONE `get_tenant_session(tenant_id)` (RLS-scoped, the operator-supplied tenant), then
commits; the two audit-chain appends (distribution + rollback-correlation) run on a
SEPARATE `get_privileged_session()` + `session.begin()` block, mirroring every other
Orchestrator write seam's session discipline. The dispatch itself is scheduled as a
FastAPI `BackgroundTask` calling the EXISTING `drive_distribution`, unmodified.

## Honesty boundaries (verbatim — non-removable)

- **This is NOT a comprehensive command center across all products.** It aggregates ONLY
  what the Orchestrator's own tables track. Delta and Rendly's own API loads and
  governance metrics are NOT included — there is no pipeline that pushes them here.
- **This is NOT automated, failure-detection-triggered rollback.** There is no autonomous
  trigger anywhere in this PR. Every rollback requires an explicit operator action
  (`ORCH_ADMIN_TOKEN` + an explicit `(tenant_id, policy_id)` target). "The orchestration
  loop detects a critical system failure" describes a capability this PR does not build.
- **This is NOT a generic rollback mechanism.** It does exactly one thing: re-submit the
  immediately-prior `policy_distributions` signed record for one `(tenant_id, policy_id)`
  pair. Rolling back a registry entry, an automation rule, or an external-gateway key
  change is out of scope — each of those already has its own narrower, purpose-built
  mutation (deregister, DELETE, revoke).
- **A rollback can only ever restore the SECOND-most-recent version, not an arbitrary
  point in history.** Rolling back twice in a row restores whatever was current two
  rollbacks ago (the new distribution the first rollback created becomes the new
  "current," and the SECOND-most-recent at that point is whatever was two steps back) —
  there is no "roll back to version N" targeting.
- **Dispatched only via this run's explicit authorization to build post-investment tasks**
  (mirrors ADR-0009→ADR-0013's identical disclosure) — the roadmap's own 🏦 label means
  this was not scheduled as next-buildable MVP work.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Cross-tenant rollback (an operator action affecting the wrong tenant's policy) | The rollback's ENTIRE lookup, insert, and target-copy run on `get_tenant_session(tenant_id)` with the operator-SUPPLIED tenant_id (Fork C) — RLS structurally confines every read/write to that tenant; there is no code path that could reach another tenant's `policy_distributions` row even given a colliding `policy_id`. |
| Rolling back with no prior version to restore | The pre-check (`len(recent) < 2`) is a genuine COUNT-before-act guard — a `409 nothing_to_roll_back_to`, never a 5xx, never a silent no-op that looks like it worked. |
| A malformed/oversized rollback request | Allow-listed fields, bounded string lengths (`tenant_id`/`policy_id` ≤ 64), and a NUL guard (reuses `boundary.contains_nul`) are all enforced at the request boundary before any DB read — never a 5xx for an ordinary validation failure. |
| Rollback re-submission diverging from the original distribution's dispatch semantics | `signed_record`/`content_hash`/`policy_version`/`policy_type` are copied BYTE-IDENTICALLY from the prior row (never reconstructed or re-derived) and dispatched through the UNMODIFIED `drive_distribution` — the rollback cannot silently alter what gets sent to Sentinel. |
| Operator-token compromise enabling unbounded rollback abuse | Same fail-closed, constant-time `_require_admin` boundary as every other admin seam (401/403, no enumeration oracle) — this PR introduces no new credential and no weaker check than the existing O-007/O-013 admin surface. |
| Tamper on the rollback-correlation chain | Append-only via BEFORE UPDATE/DELETE deny triggers + SHA-256 hash chain (mirrors every other Orchestrator chain); `validate_rollback_chain` re-verifies the full chain under the same FAIL-LOUD BYPASSRLS assertion as every other chain validator in this codebase. |
| Unbounded summary aggregation degrading the shared Postgres instance | `ORCH_COMMAND_CENTER_LOOKBACK_HOURS` bounds every windowed COUNT (Fork G) — none of the five aggregation queries scans an unbounded time range. |

## Residual risk (known, deferred)

- **No cross-product telemetry.** Delta/Rendly API loads and governance metrics are not
  aggregated here — a genuine, separate cross-product metrics pipeline (likely requiring
  each product to push its own summary, or a new shared observability surface) is
  out-of-scope future work.
- **No autonomous failure detection or autonomous rollback trigger of any kind.** Building
  one requires first agreeing on a failure taxonomy and a dry-run/safety-net design — a
  substantial, separate, genuinely risky undertaking not attempted here.
- **No "roll back to an arbitrary historical version."** Only the immediately-prior
  version is restorable per call (Honesty boundaries).
- **The windowed aggregation queries (distributions/automation/external-gateway/ingest)
  are not backed by a `created_at`/`event_timestamp` index in this migration** — they rely
  on the existing table scan cost at current data volumes. If any of these tables grows
  large enough for the bounded scan to become slow, adding an index is real, separate,
  low-risk follow-up work (this PR deliberately stays additive-only and does not ALTER any
  existing table).

## Configuration

New environment variable (resolved NON-FATALLY — absence is not fatal; no master
enable/disable switch exists here, see Fork F):

- `ORCH_COMMAND_CENTER_LOOKBACK_HOURS` — the summary's aggregation window in hours
  (default 24, ≥ 1).

## Testing

- **Unit** (`tests/unit/test_command_center_config.py`, `test_hash_chain_rollback.py`,
  `test_command_center_router.py`): env-parsing defaults/overrides/misconfiguration; the
  rollback chain's canonicalization and tamper-evidence properties; the admin-token
  boundary (401/403, byte-identical to `admin/router.py`'s); the summary's zero-fill
  behavior (repository layer monkeypatched, no DB); the rollback validation boundary (422:
  unknown field, missing field, oversized tenant_id/policy_id, NUL byte); the
  `nothing_to_roll_back_to` 409 path (mocked `list_recent_distributions_for_policy`
  returning fewer than two rows); the happy-path rollback (mocked repo layer) proving the
  new distribution copies `signed_record`/`content_hash`/`policy_version`/`policy_type`
  byte-identically from the prior row and that BOTH audit appends (distribution +
  rollback-correlation) fire with the correct arguments.
- **Integration** (`tests/integration/test_command_center_e2e.py`,
  `pytest.mark.integration`, gated by `ORCH_REQUIRE_COMMAND_CENTER_E2E=1`, fails loud if
  set but unable to run, never silently skips on CI): a NON-STUBBED path over a real DB
  proving two real distributions submitted for the same `(tenant_id, policy_id)`, then
  rolled back, produces a THIRD distribution whose `signed_record` matches the FIRST
  (the one being restored) byte-for-byte; the rollback-correlation chain records the
  correct `source_distribution_id`/`superseded_distribution_id`/`new_distribution_id`
  triple and validates in full; a rollback attempted with only one prior distribution is a
  genuine 409; the summary reflects real registry/distribution/rollback counts seeded
  directly on the privileged connection.
- `tests/integration/test_migration_roundtrip.py` updated for the new head revision
  (`0011_command_center`) and its one new table.
- `contracts/openapi.yaml` updated with the two new operations, reusing the existing
  `operatorBearer` security scheme; verified against `tests/test_contract.py`.

## Out of scope (do not build here)

Any cross-product telemetry pipeline pulling metrics from Delta or Rendly's own internals;
any autonomous failure detector or autonomous rollback trigger of any kind; a generic
"rollback anything" mechanism beyond policy distributions; rolling back to an arbitrary
historical version (only the immediately-prior version is restorable); a new index on any
existing table (Residual risk); the remaining O-015 ecosystem-integration-layer task
(predictive scaling).

## Consequences

- Operators gain a real, working, read-only fleet-health snapshot over metrics the
  Orchestrator already collects, plus one genuine, safe, reversible policy-distribution
  rollback primitive built entirely on the existing O-004 dispatch path — reusing every
  existing credential/session/RLS/audit pattern this repo already established, entirely
  additive.
- The gap between this slice and the roadmap's fuller "comprehensive command center across
  all products... automated rollback" vision is named explicitly (Honesty boundaries,
  Residual risk, Out of scope) rather than implied away, consistent with CLAUDE.md's
  mandatory honest-language rule and ADR-0009→ADR-0013's identical precedent.
- Because the rollback reuses the O-004 engine verbatim rather than inventing new dispatch
  logic, its correctness inherits directly from O-004's own already-audited behavior —
  the only genuinely new logic in this PR is "which prior record to re-submit," a small,
  reviewable surface.
