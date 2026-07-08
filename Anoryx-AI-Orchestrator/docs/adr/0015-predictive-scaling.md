# ADR-0015 — Ingest-Traffic Current-Rate Projection (not autoscaling, not an ML model)

- Status: Accepted
- Date: 2026-07-08
- Task: O-015 (fifteenth and final Orchestrator roadmap task, 🔮 SPECULATIVE tier —
  "scope may need refinement when reached")
- Builds on: ADR-0007 (O-007 admin API — the `_require_admin` operator-bearer boundary
  this reuses), ADR-0014 (O-014 command center — the SAME bounded-window aggregation
  discipline over `ingest_events`, including the TEXT-column string-formatting fix that
  ADR-0014's own e2e run caught and this task reuses directly)
- Cross-references: Delta's ADR-0011 (D-011 predictive budget forecasting) — this ADR
  deliberately reuses D-011's `current_rate_projection_v1` method-name convention and its
  "no trained model, deterministic and advisory-only" posture, for ecosystem-wide naming
  and honesty consistency between the two sibling "predictive" features.
- Supersedes: nothing. Adds one new package (`predictive_scaling`) and one new
  `PredictiveScalingSettings`; zero new tables, zero new migration, zero new hash chain
  (a pure read takes no mutating action to audit).

Unlike O-009→O-014, O-015 is 🔮 SPECULATIVE, not 🏦 POST-INVESTMENT — the roadmap's own
status legend says 🔮 tasks' "scope may need refinement when reached," which is exactly
what this ADR does; no special post-investment authorization applies to this tier.

## Context

The roadmap lists O-015 as **"Predictive scaling. Telemetry analysis from the registry,
traffic-spike prediction ('Algorithmic CFO'). Depends on: O-003, D-005."** Taken at face
value this could imply: (a) an autoscaling controller that actually resizes
infrastructure, (b) historical trend analysis over the Sentinel registry, and (c) some
integration with Delta's budget engine (D-005). None of these are buildable honestly
today:

- **"Predictive scaling" implying actual autoscaling** — there is no infrastructure
  control surface anywhere in the Orchestrator (no KEDA/HPA hook, no provisioning API);
  that capability lives, if anywhere, in `platform-infra`'s deployment tooling, not this
  codebase. Building one here would be a substantial, unreviewed, first-of-its-kind
  infrastructure-control feature with no precedent to mirror.
- **"Telemetry analysis from the registry"** — `sentinel_registry` (O-005) is a
  POINT-IN-TIME table: one row per Sentinel instance, overwritten in place by each health
  check (`health_status`, `last_checked_at`). There is no historical time-series of past
  registry states to analyze trends over. The Orchestrator's only genuinely timestamped,
  append-only, historically-queryable signal is the O-003 `ingest_events` stream.
- **"Depends on... D-005"** — no data pipeline pushes Delta's budget/spend state into the
  Orchestrator; correlating a traffic spike with a spend spike would require reaching
  into Delta's own internals, which this repo's protect-paths hook forbids for
  `Anoryx-AI-Orchestrator/` code.

This ADR resolves the tension the way D-011's own ADR-0011 resolved the identical
"predictive... modeling" ambiguity for Delta: **ship a real, honest, current-rate
projection — deterministic arithmetic, not a trained model — over the one genuine
timestamped signal this codebase actually has (`ingest_events`), and name everything
else (actual autoscaling, registry history, Delta integration) as an explicit
deferral.**

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — what "predictive scaling" means without an infrastructure-control surface | **A1**: `GET /v1/admin/traffic-forecast` is READ-ONLY. It reports a projection; it triggers NO scaling action, NO KEDA/HPA call, NO provisioning of any kind. An operator (or a future automation reading this endpoint) decides what to do with the number — this PR does not decide for them. |
| **B** — what "telemetry" means without registry history | **B1**: the forecast buckets the O-003 `ingest_events` stream (already timestamped, append-only) into two adjacent windows, not `sentinel_registry` (no history exists there to bucket). Building a registry-history table (periodic health-status snapshots) is real, separate, additive future work — named in Residual risk, not attempted here. |
| **C** — projection method | **C1**: `current_rate_projection_v1` — hold the CURRENT window's observed rate (`event_count / window_hours`) constant and project it across `horizon_hours`. Identical technique and identical method-literal to Delta's D-011 (`budget_engine`'s own forecast), for ecosystem-wide consistency. NOT a regression, NOT ARIMA/Prophet/any trained time-series model — mirrors D-011 ADR-0011 Fork 1's exact reasoning (a flat rate is far more robust to noise than a fitted slope over as few as two buckets, and is honestly labeled as such). |
| **D** — spike heuristic | **D1**: `spike_detected = (current_rate / previous_rate) >= ORCH_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD` (default 2.0×) — a single deterministic threshold comparison, advisory-only, never triggering any action. Mirrors D-011 Fork 5's "deterministic, threshold-based, advisory-only" framing. |
| **E** — previous window with zero events | **E1**: `insufficient_data: true`, `spike_ratio: null` — NEVER a divide-by-zero, and NEVER a fabricated "infinite spike" verdict. Mirrors D-011's own `INSUFFICIENT_DATA` honesty pattern (D-011 ADR-0011 §3) rather than silently defaulting to a number that implies more confidence than the data supports. |
| **F** — no persisted state | **F1**: every forecast is computed LIVE from `ingest_events` at request time — nothing is stored, cached, or historized (mirrors D-011 Fork 7's identical "no persisted state, no migration" choice). Zero new tables, zero new migration, zero new hash chain — there is no mutating action here to audit. |
| **G** — master enable/disable switch | **G1**: NONE. A pure read behind the SAME operator credential every other admin seam already requires; there is no autonomous behavior of any kind to gate (mirrors ADR-0012/ADR-0013/ADR-0014's identical "ordinary explicit-caller action, no switch needed" reasoning). |
| **H** — mounted where | **H1**: a NEW package, `predictive_scaling/router.py` — mirrors this codebase's one-package-per-O-task convention (messaging, external_gateway, command_center, automation, identity, relay, ...), rather than growing `command_center`'s own scope. |

## API additions

- `GET /v1/admin/traffic-forecast` — operator-gated. `200 {method:
  "current_rate_projection_v1", generated_at, window_hours, horizon_hours,
  current_window: {since, until, event_count, rate_per_hour}, previous_window: {...},
  projected_event_count_over_horizon, spike_ratio, spike_ratio_threshold, spike_detected,
  insufficient_data}`.

Reuses `operatorBearer` (the SAME scheme as O-005/O-007/O-013/O-014's admin seams).

## Data access

Both window counts run on the SAME `get_privileged_session()` (cross-tenant fleet
triage, mirrors every other admin read in this codebase) via
`count_ingest_events_in_window`, which reuses `count_ingest_events_since`'s
string-formatting discipline (`event_timestamp` is a caller-supplied TEXT column — an
RFC-3339 string, not a real `timestamptz` — a lesson ADR-0014's own e2e run caught the
hard way; this task reuses that fix directly rather than re-deriving it).

## Honesty boundaries (verbatim — non-removable)

- **This does NOT scale anything.** No infrastructure action of any kind is triggered.
  "Predictive scaling" in the roadmap's literal sense — a controller that actually
  resizes something — is not built here.
- **This is NOT telemetry analysis "from the registry."** It analyzes `ingest_events`,
  the Orchestrator's only genuinely historical, timestamped traffic signal.
  `sentinel_registry` has no history to analyze.
- **This is NOT a trained statistical or ML model.** `current_rate_projection_v1` is
  deterministic arithmetic — a flat rate held constant and projected forward — identical
  in spirit and in name to Delta's own D-011 forecast method.
- **This does NOT integrate with D-005 (Delta's budget engine).** No pipeline pushes
  Delta's spend state into the Orchestrator; a traffic-spike/spend-spike correlation is
  out of scope.
- **This does NOT persist forecast history.** Nothing here can later answer "was last
  week's forecast accurate" — every call is a fresh, live computation.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Unauthorized access to cross-tenant traffic volume | Same fail-closed, constant-time `_require_admin` boundary as every other admin seam (401/403, no enumeration oracle) — no new credential, no weaker check. |
| Unbounded aggregation degrading the shared Postgres instance | Exactly two bounded-window `COUNT` queries per request (`ORCH_PREDICTIVE_SCALING_WINDOW_HOURS`-sized buckets) — never an unbounded full-table scan. |
| Divide-by-zero / a fabricated spike verdict from a zero-event previous window | `insufficient_data` (Fork E) — the ratio is never computed, never defaulted to a number. |
| A malicious client crafting an ingest_events row whose `event_timestamp` string sorts outside its real chronological position (TEXT-column string-comparison caveat) | Inherited, pre-existing limitation of the `event_timestamp` TEXT column shared by `list_events`'s own `since`/`until` filters and O-014's `count_ingest_events_since` — not introduced or worsened here; named explicitly (Residual risk) rather than silently relied upon. |

## Residual risk (known, deferred)

- **No actual autoscaling action.** An operator (or a future automation) must read this
  endpoint and act; nothing here closes that loop.
- **No registry-history telemetry.** A `sentinel_registry_history` snapshot table (and
  the trend analysis it would enable) is real, separate, additive future work.
- **No Delta/D-005 integration.** Correlating ingest-traffic spikes with Delta spend
  spikes requires a cross-product data pipeline that does not exist.
- **No forecast-accuracy tracking**, identical to D-011's own named deferral — nothing
  persists a forecast to later compare against what actually happened.
- **The `event_timestamp` TEXT-column string-comparison caveat** (Threat model, last row)
  is inherited from O-003/O-006/O-014, not new here.

## Configuration

New environment variables (all resolved NON-FATALLY — absence is not fatal; no master
enable/disable switch exists here, see Fork G):

- `ORCH_PREDICTIVE_SCALING_WINDOW_HOURS` — current/previous bucket size in hours
  (default 1, ≥ 1).
- `ORCH_PREDICTIVE_SCALING_HORIZON_HOURS` — projection horizon in hours (default 24, ≥ 1).
- `ORCH_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD` — current/previous rate ratio that
  triggers `spike_detected` (default 2.0, ≥ 1.0 — a ratio below 1.0 would flag a
  DECREASE as a "spike").

## Testing

- **Unit** (`tests/unit/test_predictive_scaling_config.py`,
  `test_predictive_scaling_router.py`): env-parsing defaults/overrides/misconfiguration;
  the admin-token boundary (401/403, byte-identical to every other admin router's);
  the happy-path projection math (mocked repository counts, asserting `rate_per_hour`,
  `projected_event_count_over_horizon`, `spike_ratio`, and `spike_detected` are computed
  correctly for a genuine spike, a genuine non-spike, and an `insufficient_data` case).
- **Integration** (`tests/integration/test_predictive_scaling_e2e.py`,
  `pytest.mark.integration`, gated by `ORCH_REQUIRE_PREDICTIVE_SCALING_E2E=1`, fails loud
  if set but unable to run, never silently skips on CI): a NON-STUBBED path over a real
  DB proving real `ingest_events` seeded into the current and previous windows produce
  the correct counts/rates/projection, and that a genuine rate increase between the two
  windows sets `spike_detected: true` while a flat rate does not.
- `contracts/openapi.yaml` updated with the one new operation, reusing the existing
  `operatorBearer` security scheme; verified against `tests/test_contract.py`.

## Out of scope (do not build here)

Any actual autoscaling/infrastructure-control action; registry-history telemetry or
trend analysis; any integration with Delta/D-005; forecast-accuracy tracking; a trained
statistical or ML model of any kind.

## Consequences

- Operators (and any future automation) gain a real, honest, current-rate traffic
  projection over the Orchestrator's genuine timestamped signal — reusing the exact
  aggregation/session/auth patterns ADR-0014 already established, with zero new schema.
- This is the FINAL Orchestrator roadmap task (O-001→O-015 all shipped after this PR
  merges) — the gap between this slice and the roadmap's fuller "predictive scaling...
  Algorithmic CFO" vision is named explicitly (Honesty boundaries, Residual risk, Out of
  scope) rather than implied away, consistent with CLAUDE.md's mandatory honest-language
  rule and this entire ADR series' precedent.
- The `current_rate_projection_v1` method name is now used identically by both Delta
  (D-011) and the Orchestrator (this task) — a small, deliberate piece of ecosystem-wide
  naming consistency for "the same honest technique," not a coincidence.
