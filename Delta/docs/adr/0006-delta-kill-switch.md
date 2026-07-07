# ADR-0006 — Delta Kill-Switch (instantaneous emergency brake for unauthorized/anomalous agent transactions)

- **Status:** Proposed (awaiting human approval — STEP 1 gate)
- **Date:** 2026-07-07
- **Task:** D-006 (the emergency-brake half) · Builder: policy-engine
- **Builds on:** D-002 (#33 budget policy + emit), D-004 (#41 ingest), D-005 (#45 budget engine,
  O-004 seam, Delta signing identity), O-004 (#42 policy distribution), F-008 (policy intake +
  enforcement)
- **Delta ADR head is 0005; this is 0006.**

---

## 1. Context

D-005 (ADR-0005 §8, honest-scope) explicitly named D-006 out of scope: "a separate, faster
emergency brake for unauthorized agent transactions." D-005's own loop is real-time but still
**cumulative** — it derives spend from the ledger and only publishes once cumulative spend
crosses a period cap. That is the right mechanism for a budget. It is the *wrong* mechanism for
"this specific transaction should never have happened at all" — an agent transacting that has no
business transacting, or a single transaction so large it is itself the anomaly. Waiting for
cumulative spend to cross a cap is too slow for that case; the roadmap calls this "faster than
the budget-threshold loop."

D-006 adds a **second, independent, identity/magnitude-triggered** enforcement path that reuses
essentially all of D-005's proven machinery (the outbox, the drainer, the O-004 publisher, the
Delta signer) but fires on a **per-transaction** signal instead of a **per-period** one.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — enforcement vehicle** | Reuse the D-005 vehicle unchanged: publish a `budget_limit` record with **both caps set to 0** at `scope="agent"`. Un-kill publishes the same `policy_id` at a bumped version with caps at the locked-schema maxima. | The locked `policy.schema.json` itself documents this exact pattern ("To block all models... or set budget_limit to zero" — `ModelAllowlistPolicy` description). Zero schema change, no new `policy_type`, reuses the byte-valid D-002 emit path and the D-005 signer as-is. |
| **2 — detection signals** | Two independent, orthogonal triggers: (a) **unauthorized agent** — an opt-in per-tenant agent allow-list (`agent_authorizations`); a usage event from a non-allow-listed agent, in a tenant that HAS configured the allow-list, is unauthorized. (b) **anomalous single transaction** — a configurable absolute per-transaction cost ceiling (`DELTA_KILL_SWITCH_MAX_TX_COST_CENTS`), independent of any period accumulation. | Matches the roadmap's own wording verbatim ("an unauthorized/anomalous AI agent transaction"). Both are O(1) per-event checks — no ledger SUM — so they are structurally faster than D-005's cumulative evaluation. Both are opt-in/inert-by-default (no configured allow-list / no configured ceiling ⇒ that trigger never fires), mirroring D-005 §11's "engine inert until configured" honesty boundary — D-006 must never brick an existing tenant that has not opted in. |
| **3 — enforcement granularity** | The kill targets the **exact (tenant, team, project, agent) scope of the offending transaction** — i.e. Sentinel's own `BudgetScope.AGENT` granularity (ADR-0009: budget policies do NOT use the wildcard convention; `scope="agent"` matching requires exact team_id + project_id + agent_id, per `policy/enforcement.py::budget_matches_scope`). | This is the ONLY scope the locked schema can express without a wildcard; a tenant-wide "block this agent everywhere" is not expressible by a single `budget_limit` record. Precisely blocking the transaction's own scope is also the smaller, more conservative blast radius — it cannot collaterally block the same `agent_id` legitimately operating under a different team/project. |
| **4 — edge detection + idempotent publish** | Identical shape to ADR-0005 §3.3: a per-scope `kill_switch_state` row with a conditional `UPDATE ... WHERE state='clear'` transition — under concurrent offending events for the same scope, exactly one publishes. | Proven pattern; no new risk surface. |
| **5 — recovery (un-kill)** | Explicit operator action only, no automatic timer/expiry. `authorize_agent()` (allow-listing an agent) clears every `killed` row for that `(tenant, agent_id)` immediately, in the same transaction, publishing a refreshed (unblocking) version — it does not wait for a new inbound event (which cannot arrive from a blocked scope). A standalone `clear_kill_switch()` lets an operator override an anomaly-triggered kill without changing the allow-list. | Mirrors D-005's own "raise the cap" recovery path, but resolves D-005's known idle-tenant gap (§12 "Deferred, review LOW"): a killed scope generates no further usage events, so waiting for the next event to re-evaluate would never fire. D-006 closes that gap for its own recovery path by making the admin action itself the trigger. |
| **6 — fail posture** | Same two dangerous directions as D-005 §3.5, applied here: detection-read failure ⇒ fail-safe (never falsely kill on a transient blip); publish failure ⇒ never silently drop (durable outbox, retry, dead-letter + alert). | A kill-switch that fails open on a real threat is useless; a kill-switch that fails closed on a blip (killing a legitimate agent on a DB hiccup) is its own outage. Both are first-class, exactly as ADR-0005 treats budget enforcement. |

---

## 3. Architecture

### 3.1 Two independent triggers (pure, no I/O) — `kill_switch/triggers.py`

```
unauthorized_reason(gated: bool, authorized: bool) -> "unauthorized_agent" | None
anomalous_reason(cost_cents: int, max_single_tx_cost_cents: int | None) -> "anomalous_single_tx" | None
```

`gated` = the tenant has >=1 row in `agent_authorizations` (opted in to the allow-list). While
`gated` is false the unauthorized-agent trigger is INERT for that tenant — no allow-list
configured means D-006 imposes no new restriction (never a silent, unrequested brick of an
existing tenant). `max_single_tx_cost_cents` is `None` unless
`DELTA_KILL_SWITCH_MAX_TX_COST_CENTS` is set — inert by default.

### 3.2 Evaluation trigger — event-driven, per event, no accumulation

Fires from the same D-004 ingest post-commit hook as D-005 (`ingest/router.py`, immediately
after `evaluate_after_post`), for the single scope the just-posted event touches. Like D-005, it
is a pure post-commit side effect in its OWN tenant transaction: it never alters the ingest
response (a successful debit always returns 200; enforcement is downstream). Unlike D-005, there
is no ledger SUM — the check is a presence/absence lookup (`agent_authorizations`) plus an
integer comparison against the SINGLE event's `cost_estimate_cents` already in hand. No period,
no bucket, no accumulation — this is the "faster than the budget-threshold loop" property.

### 3.3 Edge detection + enforcement state — `kill_switch/state.py`

One row per `(tenant_id, team_id, project_id, agent_id)` (NOT per period — there is no period
here), `kill_switch_state`, tracking `clear | killed`:

- **clear -> killed**: a conditional `UPDATE ... WHERE state='clear'`; the row count decides who
  publishes — under concurrent offending events for the same scope, exactly one wins and
  publishes (mirrors ADR-0005 vector 5). `policy_id` is minted once, at first-ever detection for
  that scope (`INSERT ... ON CONFLICT DO NOTHING` then re-select, mirroring
  `budget_engine.state.get_or_create_state`), and is stable thereafter.
- **killed -> clear**: only via an explicit operator action (§2 fork 5), never automatically.
- `last_published_version` is monotonic per `policy_id` (this table's own row, not shared with
  any D-005 `budget_definitions` row — a DIFFERENT `policy_id`, so the kill-switch's cap=0 record
  and any real D-005 budget cap for the same scope are independently enforced and independently
  liftable; F-008 evaluates every matching `budget_limit` policy_id for a scope and denies if ANY
  is exceeded — `policy/enforcement.py::evaluate_budget_against` — so neither layer weakens the
  other).

### 3.4 Publish + the outbox — `kill_switch/outbox.py`, `kill_switch/drainer.py`

Identical shape to ADR-0005 §3.4: the signed decision is committed to `kill_switch_outbox` in the
SAME transaction as the state flip, before any network call (a decision is never lost even if the
process dies before the POST). The drainer reuses, UNCHANGED:

- `delta.policy.sign` (the vendored ES256 signer + the Delta signing key) — no new key custody
  surface;
- `delta.budget_engine.publisher.publish_signed_policy` (the O-004 client is generic over any
  signed `budget_limit` record; the kill-switch does not need its own copy).

Only the outbox/state persistence (different tables) and the drain loop's claim query are
kill-switch-specific; the sign + publish + classification logic is the same D-005 code, run
against a different queue.

### 3.5 The payload — `kill_switch/emit.py`

Reuses the D-002 emit vehicle unchanged (`attribution.budget_concept_to_policy_payload`):

- **kill**: `BudgetConcept(scope=AGENT, period=DAILY, limit_tokens=0, limit_cost_cents=0)`. Both
  caps are zeroed (not just cost) so the block holds regardless of which dimension F-008 checks
  first. `period` is a required schema field but is immaterial to the effect: `used >= 0` and
  `0 > 0` is never true, so a zero cap denies every request with a positive estimate in EVERY
  period bucket, unconditionally, from the moment `effective_from` passes.
- **clear**: the same `policy_id`, a bumped `policy_version`, caps at the locked-schema maxima
  (`MAX_BUDGET_TOKENS`, `MAX_BUDGET_COST_CENTS`) — "no kill-switch-layer restriction," not "no
  restriction at all" (a real D-005 budget for the same scope, if any, keeps enforcing under its
  own, different, `policy_id`).

No schema change; `git diff` of `policy.schema.json` stays empty (proven by the same guard test
pattern as ADR-0005 §4).

### 3.6 Authorization store — `kill_switch/authorizations.py`

`agent_authorizations`: `(tenant_id, agent_id)` — a TENANT-WIDE identity allow-list (not scoped
to team/project; the admin concept is "this agent is known-good for this tenant," independent of
which team/project it is invoked under). `authorize_agent()` inserts (idempotent,
`ON CONFLICT DO NOTHING`) and, in the SAME transaction, finds every `kill_switch_state` row for
`(tenant_id, agent_id)` still `killed` — across ALL team/project scopes that agent has ever
offended under — and clears each one (§3.3, §2 fork 5). `revoke_agent()` deletes the allow-list
row; it does not retroactively kill anything (future events re-evaluate under the now-narrower
allow-list, same as D-005's budget-raise path only takes effect going forward). Seeding is an
internal function/CLI path, same convention as D-005's `create_budget` — a full admin UI is
deferred (mirrors D-007 for budgets).

### 3.7 Fail posture (mirrors ADR-0005 §3.5)

- **Detection-read failure (allow-list lookup fails) -> fail-SAFE, never wrongly kill.** A
  transient read error must never kill an authorized agent on a blip. Transient classification
  reuses `ingest.errors.is_transient` (the same OSError/TimeoutError-inclusive set — the
  F-007-FU lesson). Non-transient errors are logged loud, never silently swallowed.
- **Publish failure -> never silently drop.** Identical to D-005: the decision is durable in
  `kill_switch_outbox` before any network call; the drainer retries with bounded backoff; on
  exhaustion the row is dead-lettered (`failed`) with a loud alert. A missing/invalid signing key
  is treated as a publish failure (decision retained, alerted), never a silent drop and never a
  fail-open.

## 4. Tenant isolation

Both new tables (`agent_authorizations`, `kill_switch_state`) plus `kill_switch_outbox` are RLS
`ENABLE + FORCE` under `delta_app` (NOBYPASSRLS) with the identical strict fail-closed NULLIF
predicate as D-003/D-005. An unset/empty GUC collapses to zero rows, never a widen. The published
kill/clear record's scope IDs come from the triggering event's own attribution (server-derived,
never client-overridable at the policy layer) and are bound into the signed JWS exactly as D-005
binds a budget's scope — a tampered scope cannot widen reach.

## 5. Data model (migration 0004, down_revision "0003")

Three tables in the `delta` schema, RLS-scoped to `delta_app`, reversible (mirrors 0003's
migration-roundtrip proof). Mutable-within-tenant (state transitions, delivery status, allow-list
membership) — `delta_app` is granted `SELECT, INSERT, UPDATE` (`agent_authorizations` also needs
`DELETE` for `revoke_agent`; the other two tables never delete, matching D-005).

- **`agent_authorizations`** — `(tenant_id, agent_id)` PK. `authorized_at`.
- **`kill_switch_state`** — `kill_id` PK, `(tenant_id, team_id, project_id, agent_id)` UNIQUE (the
  conditional-transition key), `policy_id`, `state ('clear'|'killed')`, `reason` (nullable,
  `'unauthorized_agent'|'anomalous_single_tx'` — the last trigger, kept for audit even after
  clearing), `last_published_version`, `updated_at`.
- **`kill_switch_outbox`** — `outbox_id` PK, FK `(kill_id, tenant_id)` -> `kill_switch_state`,
  `policy_id`, `policy_version`, `transition ('kill'|'clear')`, `policy_payload JSONB`,
  `distribution_id`, `state ('pending'|'distributed'|'failed')`, `attempts`, `next_attempt_at`,
  `last_error`, `created_at`. UNIQUE `(tenant_id, policy_id, policy_version)` (idempotent decision,
  defence-in-depth on the conditional transition, mirrors D-005).

## 6. Threat model (vectors -> tests)

| # | Vector | Mitigation | Test |
|---|---|---|---|
| 1 | Cross-tenant kill/authorization read/write | RLS FORCE + NULLIF predicate on all 3 tables | `test_rls_isolation` |
| 2 | Unset/empty GUC widens rows | NULLIF -> zero rows; `get_tenant_session` fail-closed | (shared with D-003/D-005 proof; exercised via `tenant_session` fixture) |
| 3 | False-positive kill on a transient detection-read error | fail-SAFE: transient classify (incl. OSError/TimeoutError) -> no kill published | `test_transient_detect_error_no_false_kill` |
| 4 | Missed-kill: publish fails silently | durable outbox; retry; `failed` + alert, never dropped | `test_o004_down_decision_not_lost` |
| 5 | Race: concurrent offending events, same scope | conditional `UPDATE ... WHERE state='clear'`; rowcount gates publish | `test_concurrent_offense_one_publish` |
| 6 | Kill-switch policy_id collides with / clobbers a D-005 budget policy_id for the same scope | independently minted `policy_id` (own uuid4, own table); both enforced independently by F-008 (AND semantics) | `test_kill_policy_id_independent_of_budget` |
| 7 | Cross-tenant kill (tenant A's offense kills tenant B's agent) | RLS + per-tenant scope key; B never evaluated by A's event | `test_tenant_a_offense_not_kill_b` |
| 8 | Un-kill publishes an invalid / unsigned record | reuses the proven D-002 emit path + D-005 signer; byte-valid against the UNMODIFIED locked schema | `test_kill_and_clear_payload_schema_valid` |
| 9 | Allow-list opt-in tenant with zero rows gets bricked by the mere existence of the feature | `gated` check: zero `agent_authorizations` rows for a tenant = inert (no unauthorized-agent kill ever fires) | `test_ungated_tenant_never_killed_for_identity` |
| 10 | Un-kill only checks the exact killed scope, missing sibling team/project kills for the same agent | `authorize_agent` clears EVERY `killed` row for `(tenant, agent_id)`, not just one | `test_authorize_clears_all_scopes_for_agent` |

## 7. Honesty boundary (what D-006 is NOT)

- **Not** a statistical/ML anomaly detector — "anomalous" here is a deliberately simple, honest,
  deterministic absolute per-transaction ceiling (opt-in, tunable), not a learned baseline. A
  velocity/z-score detector is a natural D-011/D-012 (predictive optimization / anomaly detection)
  follow-on, not claimed here.
- **Not** a tenant-wide "block this agent everywhere" switch — the locked schema's `scope="agent"`
  is exact-match on team+project+agent (no wildcard for budget policies); D-006 kills the
  transaction's own scope, and a rogue agent operating under multiple team/project scopes
  accumulates one kill record per scope it is first caught in.
- **Not** proven against the live Sentinel gateway block (same honesty boundary as ADR-0005 §8):
  the full Delta -> Orchestrator -> Sentinel compose is X-003.
- **Not** a replacement for D-005 — both run, independently, side by side.

## 8. Consequences

- **Positive:** closes the D-005 honesty-boundary gap explicitly named in ADR-0005 §8; reuses
  ~90% of D-005's proven, audited machinery (signer, outbox pattern, O-004 publisher, emit
  vehicle) with a new, small, independently-testable detection layer; resolves D-005's own
  idle-tenant recovery gap for its own un-kill path.
- **Negative / accepted:** the anomaly ceiling is a blunt absolute threshold, not adaptive; a
  legitimate one-off large transaction can trip it (opt-in and tunable, so a tenant that does not
  want this trades it off by leaving the env var unset). The unauthorized-agent allow-list is
  opt-in per tenant (a tenant that never configures it gets no identity-based protection) — an
  explicit choice to avoid silently bricking existing tenants (vector 9).
