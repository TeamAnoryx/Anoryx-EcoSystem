# ADR-0014 — Command Dashboard Summary + Health-Cycle Auto-Rollback Circuit-Breaker

- Status: Accepted
- Date: 2026-07-08
- Task: O-014 (fourteenth Orchestrator task; this run's roadmap-mechanical selection is
  "first unchecked task whose ID starts with O-" — the checklist shows O-007 through O-013
  already shipped, so O-014 is next regardless of its own 🏦 POST-INVESTMENT label)
- Builds on: ADR-0005 (O-005 registry + health cycle — `run_health_cycle`,
  `effective_health_status`, `sentinel_registry_audit_log`), ADR-0007 (O-007 admin API — the
  `_require_admin` operator-bearer boundary and the cross-tenant metadata-only admin-read
  shape this reuses verbatim), ADR-0013 (the most recent precedent for scoping a 🏦 task down
  to a real, honest, additive slice and naming the gap explicitly)
- Supersedes: nothing. Adds one read endpoint, one registry-mutation function, and a few lines
  inside the existing health cycle. No migration, no existing seam, schema, or credential is
  altered — see Fork F for why a migration was deliberately avoided (a real failure this ADR's
  first draft did not anticipate, caught by actually running the CI-mirrored suite locally
  before pushing).

This run's default posture is to stop in front of the 🏦 POST-INVESTMENT gate; the task
selection rule handed to this run ("find the first unchecked O- task, build it") does not
carve out an exception for the label, and the checklist shows every prior 🏦 Orchestrator task
(O-009→O-013) was already built under the identical standing rationale recorded in their own
ADRs. This ADR follows that same precedent rather than reopening it.

## Context

The roadmap lists O-014 as **"Command dashboard + automated rollback. Comprehensive command
center (system health, API loads, governance metrics across all products) + automated
rollback if the orchestration loop detects a critical system failure."** As written this is
not buildable as a single, honest PR today, for the same two reasons every prior Phase-2 ADR
in this series has named:

- **"across all products"** implies the Orchestrator can see Sentinel/Delta/Rendly internals
  (API load, governance metrics) beyond what already flows through its own ingest/registry/
  distribution seams. No such visibility exists, and CLAUDE.md's protect-paths boundary means
  this repo's code must never reach into another product's tree to fetch more.
- **"automated rollback ... critical system failure"** is undefined without a concrete
  failure signal and a concrete rollback action. The Orchestrator has no deployment/release
  tooling access (no Helm/K8s API, no CI trigger) to "roll back" an arbitrary deployment.

This ADR resolves that tension the way ADR-0009→ADR-0013 resolved their own literal roadmap
text: ship the smallest genuinely useful, honest slice of "command dashboard" and "automated
rollback" that is concretely buildable from what the Orchestrator ALREADY tracks, and name
everything else as an explicit, non-implied deferral.

The one piece of this repo that already has a real, well-defined "critical system failure"
signal is O-005's health cycle: a registered Sentinel transitioning to `unreachable`. And the
one piece that already has a real, safe "rollback" action available to it is the SAME
registry the health cycle already writes to: disabling a target removes it from both the
coordinated push's target selection (`coordinator._select_targets`) and any future
distribution fan-out — a genuine, immediate reduction of blast radius, not a cosmetic flag
flip.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — what "command dashboard ... across all products" means without cross-product visibility | **A1**: `GET /v1/admin/dashboard/summary`, a bounded, operator-gated (`ORCH_ADMIN_TOKEN`, reuses `_require_admin` verbatim) aggregation over data the Orchestrator's OWN existing seams already expose: registry health/enabled counts (O-005's `sentinel_registry`), a distribution-state breakdown over the `limit` most-recent policy distributions (O-004's `policy_distributions`, the same bounded page `/v1/admin/distributions/recent` already serves), and the `limit` most-recent auto-rollback circuit-breaker trips (this ADR's own new signal, an ordinary `disable` action filtered by its `error_reason` prefix — see Fork F). No new tables — every field is a read over rows that already exist for other reasons. |
| **B** — "critical system failure" without cross-product telemetry | **B1**: the ONE concrete, already-computed failure signal this repo owns: a registered-and-ENABLED Sentinel whose O-005 health cycle observes it transition to `health_status = unreachable`. Not "any critical system failure across the ecosystem" — one specific, already-real signal, extended rather than invented. |
| **C** — "automated rollback" without deployment tooling | **C1**: a circuit-breaker, not a deployment rollback. `coordination.registry.auto_disable_sentinel` sets `enabled = False` on the just-tripped target inside `run_health_cycle`, in the SAME cycle that observed the transition — removing it from `coordinator._select_targets` (skip-reason `disabled`) and therefore from every future coordinated push, immediately. This is "rolling back" the Orchestrator's OWN routing decision to trust that target, not rolling back Sentinel's, Delta's, or Rendly's deployed code — a category the Orchestrator has no tooling to act on at all. |
| **D** — master enable/disable switch | **D1**: YES, `ORCH_AUTO_ROLLBACK_ENABLED` (default `false`) — mirrors O-011's `ORCH_AUTOMATION_ENABLED` (Fork E there) for the identical reason: this is NEW AUTONOMOUS behavior (the system disables a registered target without an operator asking it to), so an existing deployment must not silently start auto-disabling targets merely by upgrading. With the switch off, `run_health_cycle`'s behavior is byte-identical to pre-O-014 (verified by the e2e's `rollback_off` control case). The dashboard READ (`GET /v1/admin/dashboard/summary`) is NOT gated by this switch — an operator can always see the (possibly empty) rollback history, mirroring how O-013's key issuance is unaffected by its own read-path switch. |
| **E** — recovery semantics | **E1**: ONE-WAY. There is no auto re-enable. A target that recovers (starts answering health probes again) stays `enabled = False` until an operator explicitly re-enables it via the EXISTING `PATCH /v1/registry/sentinels/{id}` seam (`{"enabled": true}` — no new endpoint). Auto-recovering a flaky target risks flapping (rapid disable/enable cycling as a marginal target crosses the threshold repeatedly); requiring a human to confirm the incident is resolved is the conservative default, consistent with CLAUDE.md's "risk reduction" framing over an implied "self-healing" claim this ADR does not make. |
| **F** — attribution / audit semantics | **F1 (revised in-flight — see note below)**: reuse the EXISTING `disable` registry-audit action rather than adding a new `auto_disable` value. `auto_disable_sentinel` writes `action="disable"` with `error_reason` stamped `registry.AUTO_ROLLBACK_REASON_PREFIX` (`"auto_rollback:"`) + the probe reason (e.g. `auto_rollback:connect_error`) — a manual `PATCH .../enabled=false` NEVER sets `error_reason`, so the prefix is an unambiguous, queryable "was this automatic?" signal without widening the closed `action` set. `list_recent_registry_audit_admin` gained an `error_reason_prefix` filter (in addition to its existing `action` filter) so the dashboard's rollback view queries `action="disable"` + `error_reason_prefix="auto_rollback:"`. |
| **G** — idempotency under repeated cycles | **G1**: `auto_disable_sentinel` re-checks `enabled` INSIDE its own privileged transaction immediately before writing (a fresh read, not the caller's possibly-stale snapshot) and is a no-op (returns `None`, appends nothing) if the target is already disabled or no longer registered. `run_health_cycle` additionally only ATTEMPTS the call for a target that was enabled at the START of the current cycle (`was_enabled`, captured before the probe) — belt-and-braces, so an ongoing outage produces exactly ONE auto-rollback audit link, not one per health-check interval. The e2e proves a second cycle against the still-down, now-disabled target adds no new link (and does not even re-probe it — disabled targets are already skipped by the pre-existing `if not sentinel.get("enabled", True): continue` branch). |

**Note on Fork F's revision.** The first draft of this ADR chose a NEW `auto_disable` action
value (mirroring how `action` is a closed, migration-gated enum elsewhere in this repo — the
CRIT-2-style discipline banked in the roadmap's process rules). Running the full CI-mirrored
suite locally (fresh Postgres, `python3.12`, the exact `ruff`/`black`/`pytest` invocations CI
uses) before pushing surfaced a REAL failure that discovery would have missed:
`sentinel_registry_audit_log` is append-only and — by `clean_registry`'s OWN documented
design ("the append-only audit log is left intact") — accumulates rows across the ENTIRE
integration test session, not just within one test. The very first e2e test that wrote an
`auto_disable` row made `tests/integration/test_migration_roundtrip.py`'s `downgrade base`
step fail: narrowing `ck_sral_action` back to five values via `ALTER TABLE ... ADD CONSTRAINT`
is rejected by Postgres the instant a live row violates it, and an append-only chain cannot be
DELETEd or UPDATEd to work around that without breaking hash-chain integrity for every
subsequent row. Rather than accept a downgrade that is guaranteed to fail in this repo's own
test session (not just a theoretical edge case), Fork F was revised to avoid touching
`action`'s closed set at all — a strictly smaller, migration-free change with the identical
attribution guarantee. This is exactly the kind of drift a "trust CI on a fresh DB" run is
supposed to catch; it is recorded here rather than silently fixed, per the roadmap's own
banked-rule #3 discipline (verify before declaring done).

## API additions

- `GET /v1/admin/dashboard/summary?limit=` — operator-gated (mirrors the O-007 admin reads'
  `operatorBearer` scheme exactly). `200 {sentinels: {total, by_health_status, by_enabled},
  recent_distributions: {window, by_state}, recent_auto_rollbacks: {window, count, events}}` /
  `401` (missing/unconfigured token) / `403` (wrong token). `limit` reuses the shared `Limit`
  parameter (default 50, clamped 1–200) that bounds BOTH the distribution-state window and the
  rollback-event page, mirroring `/v1/admin/distributions/recent`'s identical clamp.

No new mutation endpoint: the circuit-breaker fires only from inside `run_health_cycle`
(itself already exposed via the EXISTING `POST /v1/registry/health-check`, unchanged) — there
is deliberately no direct "trip the breaker" API, since that would just be a second way to
call the existing `PATCH .../enabled=false`.

## Data access

`dashboard_summary` runs entirely on `get_privileged_session()` (registry + registry-audit
tables carry no RLS; `policy_distributions` reads reuse the SAME privileged, cross-tenant
posture the O-007 `/v1/admin/distributions/recent` read already established — no NEW
data-access pattern). `auto_disable_sentinel` mirrors `register_sentinel`/`modify_sentinel`'s
existing shape: one privileged transaction, re-check-then-write, then an audit-link append in
the same transaction (atomic — the row and its link commit together).

## Honesty boundaries (verbatim — non-removable)

- **This is NOT "a comprehensive command center with system health, API loads, and governance
  metrics across all products."** It covers only what the Orchestrator's own ingest/registry/
  distribution seams already track about itself. Sentinel's, Delta's, and Rendly's own
  internal health, load, and governance metrics are not visible to the Orchestrator and are
  not represented here.
- **This is NOT automated rollback of a deployment, a release, or another product's code.**
  The single automated action this ADR ships is disabling ONE registered Sentinel target in
  the Orchestrator's own routing registry — removing it from future coordinated pushes. It
  never touches Sentinel's, Delta's, or Rendly's running processes, deployed artifacts, or
  infrastructure.
- **"Critical system failure" here means exactly one thing**: a previously-enabled registered
  Sentinel's O-005 health probe reaching the `unreachable` tier. Degraded-but-reachable
  targets, capability mismatches, and any failure mode outside the health cycle's own
  reachability probe are NOT covered.
- **There is no automatic recovery.** A target that starts answering health probes again
  stays disabled until an operator manually re-enables it. This is a deliberate one-way trip
  (Fork E), not an oversight.
- **The distribution-state breakdown is over the most-recent N distributions (bounded by
  `limit`, capped at 200), not a true count over a time window.** A tenant with very high
  distribution volume will see the breakdown skew toward the last few minutes, not represent
  "all distributions today." This mirrors the pre-existing `/v1/admin/distributions/recent`
  page's identical bound — the dashboard does not introduce a new limitation, it surfaces the
  existing one in a new aggregate view.
- **Dispatched only via this run's mechanical roadmap-order selection rule, not a
  reassessment of the 🏦 label** (mirrors ADR-0009→ADR-0013's identical disclosure) — the
  roadmap's own 🏦 marking means this was not scheduled as next-buildable MVP work by the
  product owner's own sequencing.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Unauthorized dashboard read leaking fleet-wide operational data | Same `_require_admin` fail-closed boundary as every other O-007 admin read (401 missing/unconfigured, 403 mismatch, constant-time compare) — no new trust root. |
| A malicious/compromised caller forging an auto-rollback audit entry to hide a real operator action | `auto_disable_sentinel` is invoked ONLY from `coordination.health.run_health_cycle`, never reachable from any HTTP router — there is no endpoint that lets a caller supply an `error_reason` with the `auto_rollback:` prefix directly (the existing `PATCH` seam never accepts `error_reason` at all); the audit chain is append-only (deny-triggers) regardless. |
| Alert fatigue / audit-spam from a flapping or persistently-down target | The idempotency re-check (Fork G) guarantees exactly one auto-rollback link per outage, not one per health-check interval; the e2e proves a second cycle against the same down target adds nothing. |
| A single flaky probe (transient network blip) causing an unwarranted circuit trip | Reuses O-005's EXISTING `unreachable_threshold`/staleness machinery unchanged — a target only reaches `unreachable` (the ONLY status this ADR reacts to) after the SAME consecutive-failure escalation that already gated the coordinated push's health filter; this ADR adds no new, weaker threshold. |
| Cross-tenant data leakage via the dashboard | The dashboard is OPERATOR-scoped and intentionally cross-tenant by design (fleet triage), exactly like every other O-007 admin read — never a tenant-facing seam; `recent_distributions`/`recent_auto_rollbacks` never include a signed policy body, `content_hash`, `endpoint`, or `capabilities` (allow-listed projections, mirrors the existing admin reads' "no payload" discipline). |
| Flapping (rapid disable/enable cycling) from an automatic recovery mechanism | There IS no automatic recovery (Fork E) — this entire threat class does not exist in this design by construction. |
| Tamper on the audit chain | Unchanged: append-only via the EXISTING `deny_registry_audit_modification()` trigger pair; `validate_registry_chain` (unchanged) still re-verifies the full chain including the new auto-rollback-flavored `disable` links, proven directly by the e2e. |

## Residual risk (known, deferred)

- **No cross-product visibility.** The dashboard cannot and does not represent Sentinel's,
  Delta's, or Rendly's own health/load/governance state — only what already flows through the
  Orchestrator. A genuinely cross-product command center requires each product to expose its
  own operator-readable health surface and the Orchestrator to aggregate THOSE, which is real,
  separate, out-of-scope future work (and would itself need its own authenticated seam per
  product, per CLAUDE.md's protect-paths boundary).
- **The circuit-breaker's only signal is registry health-probe unreachability.** A Sentinel
  that answers `/healthz` but is otherwise malfunctioning (e.g. silently failing to enforce
  policy) is invisible to this mechanism — "healthy" here inherits O-005's own honesty
  boundary (reachable ≠ verified-enforcing).
- **No automatic recovery** means a transient outage requires an operator action to restore
  routing even after the target is genuinely healthy again — an intentional tradeoff (Fork E),
  not free.
- **Distribution-state breakdown is a bounded recent-N window, not a time-windowed count**
  (see Honesty boundaries) — a follow-up `GROUP BY state` time-bucketed aggregation is real,
  separate future work if operators need it.

## Configuration

New environment variable (resolved NON-FATALLY — absence is not fatal):

- `ORCH_AUTO_ROLLBACK_ENABLED` — master switch for the circuit-breaker (default `false`; see
  Fork D). The dashboard read is unaffected by this flag.

## Testing

- **Unit** (`tests/unit/test_coordination_config.py`, `tests/unit/test_admin_router.py`):
  env-parsing default/override for `ORCH_AUTO_ROLLBACK_ENABLED`; the dashboard endpoint's
  operator-auth boundary (401/403/fail-closed, added to the shared `_ROUTES` parametrization
  so it inherits the SAME boundary tests as every other admin read); response shape and
  count-aggregation correctness with the repository layer monkeypatched (mirrors
  `test_recent_distributions_is_cross_tenant_and_never_leaks_policy_body`'s pattern — no DB);
  the `limit` clamp applied identically to both the distribution and rollback repo calls;
  confirmation that `endpoint`/`capabilities` never appear in a rollback-event body.
- **Integration** (`tests/integration/test_coordination_e2e.py::test_auto_rollback_off_by_default_e2e`
  + `::test_auto_rollback_trips_and_is_idempotent_e2e`, `pytest.mark.integration`, reuses the
  SAME `coordination_ready` fail-not-skip gate as the existing O-005 e2e — no new skip-gate
  env var, since they share that file's fixtures; split into TWO tests, each with its own
  `clean_registry`, specifically so a second health cycle in the trip test can never
  re-evaluate the OTHER test's already-stopped control shim — the exact cross-contamination
  a single combined test hit during local verification): non-stubbed paths over a real DB and
  real stopped loopback Sentinel shims proving (1) with the switch OFF, an unreachable target
  stays enabled — byte-identical pre-O-014 behavior, and no auto-rollback-flavored `disable`
  link is written; (2) with the switch ON, a currently-enabled target that goes unreachable is
  auto-disabled in the SAME cycle, surfaced as `auto_rollback: true` in that cycle's
  per-sentinel result; (3) the trip is chain-audited as `action="disable"` with an
  `auto_rollback:`-prefixed `error_reason`; (4) `validate_registry_chain` still passes with the
  new link present; (5) a second cycle against the still-down, now-disabled target adds no
  further such link (idempotent).
- `tests/integration/test_migration_roundtrip.py`'s head assertion and docstring updated to
  record WHY O-014 added no migration (see Fork F's revision note) — the head stays
  `0010_external_gateway`, `_TABLES` is unchanged.
- `contracts/openapi.yaml` updated with the new operation + `DashboardSummary`/
  `RegistryAuditSummary` schemas, reusing the existing `operatorBearer`/`mutualTLS` security
  scheme and the shared `Limit` parameter; verified against `tests/test_contract.py`
  (including `test_mutualtls_applied_to_every_operation`).

## Out of scope (do not build here)

A true cross-product command center (Sentinel/Delta/Rendly's own health/load/governance
surfaces); automated rollback of an actual deployment, release, or another product's running
code; automatic re-enable / self-healing of a recovered target; a time-windowed (as opposed to
bounded-recent-N) distribution-state aggregation; alerting/notification delivery (Slack/email/
PagerDuty) on a circuit-breaker trip — the dashboard is pull-based (an operator loads it),
not push-based, in v1; any new HTTP endpoint to trip or reset the breaker directly (the
existing `PATCH /v1/registry/sentinels/{id}` already covers manual reset).

## Consequences

- The Orchestrator gains a real, honest, additive command-dashboard read and its first
  autonomous protective action, both built entirely from data and machinery this repo already
  owns — no existing seam, schema, or credential changed, and the new autonomous behavior
  ships OFF by default.
- The gap between this slice and the roadmap's fuller "comprehensive command center ... across
  all products ... automated rollback" vision is named explicitly (Honesty boundaries,
  Residual risk, Out of scope) rather than implied away, consistent with CLAUDE.md's mandatory
  honest-language rule and ADR-0009→ADR-0013's identical precedent.
- The auto-rollback / manual-disable split via `error_reason` prefix (Fork F) establishes a
  reusable pattern for future automated registry actions that need to stay attributable
  without widening a closed, append-only-audited enum — and its revision note records a real
  lesson: an append-only audit table that accumulates data across a whole test session cannot
  safely have its CHECK constraint narrowed again, so widening such a constraint for a new
  action value should be treated as effectively one-way, not casually "reversible."
