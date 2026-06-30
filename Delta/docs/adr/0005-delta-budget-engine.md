# ADR-0005 — Delta Budget Engine (real-time spend-vs-budget enforcement)

- **Status:** Proposed (awaiting human approval — STEP 1 gate)
- **Date:** 2026-06-30
- **Task:** D-005 (the killer-feature half) · Builder: policy-engine
- **Builds on:** D-002 (#33 budget policy + emit), D-003 (#39 ledger), D-004 (#41 ingest),
  O-004 (#42 policy distribution), F-008 (policy intake + enforcement, ADR-0009)
- **Supersedes/depends ADRs:** Delta ADR head is 0004; this is **0005**.

---

## 1. Context

Delta is the spend authority in the ecosystem loop:

```
Sentinel → (usage events) → Orchestrator → Delta ledger
Delta → (budget-enforcement policy) → Orchestrator (O-004) → Sentinel (F-008) → blocks the scope
```

D-005 closes the **enforcement** half on the Delta side: derive authoritative cumulative
spend from the D-003 ledger, evaluate it against configured budgets in real time, emit
advisory alerts at soft thresholds, and — when cumulative spend crosses a hard cap — **sign
and publish** a budget-enforcement policy to the O-004 distribution seam so Sentinel's F-008
blocks the scope. **This is enterprise financial guardrails enforced in the security path.**

**Risk: HIGH.** This code autonomously cuts off a paying tenant's AI access. A wrong decision
in either direction is severe:
- **FALSE enforcement** — publishing when spend is NOT actually over budget → wrongly cuts off
  an under-budget tenant.
- **MISSED enforcement** — spend is over the cap but no policy is published, or a policy was
  decided but silently lost in transit → spend runs unbounded past the cap.

Both are first-class design constraints (§9, §11).

### 1.1 CONFIRM A (gating dependency) — PASS, with a premise correction

O-004 (#42, `9f101b0`) is **merged to origin/main** and its receive-policy seam is
**runnable** (real router/engine/DB, zero stub in `src/`). D-005 proceeds.

**The original D-005 brief had the signing boundary inverted.** It assumed "O-004 signs on
Delta's behalf; Delta only publishes." The merged O-004 (ADR-0004 **Fork A**) is **pass-through**:
`sign_on_behalf` is hard-disabled (`enum:[false]`, 422 otherwise), O-004 never holds Delta's
key, and **Sentinel `intake_policy()` is the verifying authority**. Therefore **Delta (D-005)
must sign the policy itself** (ES256 compact-JWS conforming to the LOCKED
`Anoryx-Sentinel/contracts/policy.schema.json`). Delta has no signing identity today
(`_SIG` in the D-002 tests is a dummy). **D-005 owns building the Delta signing identity** —
a deliberate scope expansion, approved by the maintainer.

### 1.2 CONFIRM B (constraint, not a fork)

Warnings are **Delta-side advisory only** (D-002 Fork 1b). The signed policy carries **only the
hard cap** (D-002 `to_policy_payload` → `attribution.budget_concept_to_policy_payload` drops
warnings by construction). D-005 emits warning alerts at soft thresholds, but **no warning path
can publish a policy or trigger a hard block** (vector 10).

---

## 2. Decision summary (forks)

| Fork | Decision | One-line rationale |
|---|---|---|
| **1 — enforcement vehicle** | **1a: publish the real authoritative cap** as a `budget_limit` | reuses the proven D-002 emit, byte-valid against the UNMODIFIED locked variant, **zero schema change, no new policy_type**; F-008 enforces natively |
| **2 — spend signal + trigger** | **2a: derive from the D-003 ledger, event-driven on append** | single source of truth (the append-only ledger); meets sub-second; no polling |
| **3 — edge detection + idempotent publish** | **3a: edge-triggered, per-scope enforcement state** | exactly one publish per under→over crossing; un-enforce on budget-raise via bumped version |
| **4 — fail posture** | eval-fail = never wrongly enforce; publish-fail = transactional outbox + retry + DLQ, never silently drop | a financial guardrail must fail dangerously in neither direction |
| **signer coupling** | **vendor a byte-identical signer in Delta + a conformance test** vs Sentinel `policy.crypto` | Delta stays independently deployable while provably producing intake-valid bytes |

---

## 3. Architecture

### 3.1 Spend signal (Fork 2a) — derived, integer cents, never stored

Cumulative spend for a scope is a **pure `SUM` over the append-only ledger**, exactly like the
D-003 balance primitives (`balances._movement`). A new engine primitive:

```
scope_spend_cents(session, scope, *, tenant/team/project/agent_id, currency,
                  period_start, period_end) -> int
  SUM(CASE WHEN direction='debit' THEN amount_minor_units ELSE -amount_minor_units END)
  FROM ledger_entries JOIN accounts USING (account_id)
  WHERE accounts.type = 'expense'  AND accounts.currency = <budget currency>
    AND timestamp >= period_start AND timestamp < period_end   -- half-open, the WHOLE period
    AND <scope-id columns match the budget's scope>            -- tenant (RLS) + team/project/agent
  -- NET debit-credit over the EXPENSE account: a D-003 reversal (credit on expense) cancels
  -- its original debit so a reversed usage nets to 0. A raw all-account debit sum would
  -- double-count the reversal's contra (LIABILITY) DEBIT = 2x cost = FALSE enforce (review HIGH).
```

- Runs on a `get_tenant_session` (RLS confines every row to the tenant — vector 8).
- `amount_minor_units` is `BIGINT` integer cents. **No float anywhere in the spend-vs-cap
  comparison** (`used_cents > cap_cents` and `used_tokens > cap_tokens`, both integer) — a float
  boundary error flips the decision (vector 4).
- `period_start`/`period_end` are the bucket boundaries from the budget's `period`
  (hourly/daily/monthly), computed in UTC. The window is the WHOLE current period, not
  `[start, now)`, so a slightly-future-skewed event within the period still counts.
- **Version monotonicity (review HIGH-1):** `policy_version` is monotonic per `policy_id`
  GLOBALLY (the outbox UNIQUE and Sentinel's replay protection are per-policy_id, not
  per-period), so a new period's enforcement-state row seeds `last_published_version` from the
  global max for that (tenant, budget) — never resets to 0 (else a re-used version's outbox
  INSERT silently no-ops = missed enforcement).
- Token spend (`tokens_in + tokens_out`) is NOT on `ledger_entries` (the ledger stores cost
  cents only). D-005 enforces the **cost** cap from the ledger; a token cap, if set, is enforced
  by F-008 against its own token counter once the policy is published. Delta's authoritative
  signal is cost; this is stated honestly (the ledger is a cost ledger).

### 3.2 Evaluation trigger (Fork 2a) — event-driven, affected scope only

Evaluation fires **after `post_usage` commits** in the D-004 ingest path
(`ingest/router.py:120`, after the debit is durable), for **only the scope(s) the event
touches** (its tenant + team/project/agent). It is a **post-commit side-effect**: it runs in a
**separate** tenant transaction and **never alters the ingest response** — a successful debit
always returns 200 regardless of what evaluation does (the ledger is the authority; enforcement
is downstream). Evaluation failures are handled by §3.5, never by failing the ingest.

### 3.3 Edge detection + enforcement state (Fork 3a)

A per-`(tenant_id, scope, team_id, project_id, agent_id, period_bucket)` **enforcement-state**
row tracks `under | enforced`. On evaluation:

- **under → over** (spend crossed the cap): flip to `enforced` and queue a publish — but only
  if the flip actually happened. The flip is a **conditional transition**:
  `UPDATE budget_enforcement_state SET state='enforced', ... WHERE <key> AND state='under'`.
  The row count (1 vs 0) decides who publishes — under concurrent appends both crossing the cap,
  **exactly one** transaction wins the flip and publishes (vector 5). The state flip and the
  publish-outbox insert happen in **one transaction** (§3.4).
- **over → under** (budget raised above spend, or the period bucket rolled over): flip to
  `under` and publish a **refreshed cap** at a bumped `policy_version` so F-008's view reflects
  the higher cap and unblocks the tenant (no stuck-blocked tenant — vector 6). `period_bucket`
  in the key means a new period naturally starts `under` (a fresh budget window).
- `policy_version` is **monotonic per `policy_id`** and persisted on the state row; Sentinel
  rejects replay (`version <= current_max`), so every publish increments.

### 3.4 Publish (Fork 1a) + the outbox

On a state transition that requires publishing, in the SAME transaction as the flip:

1. Build the cap policy via the **D-002 emit path** (`BudgetConcept` from the budget definition
   → `budget_concept_to_policy_payload(policy_id, policy_version, effective_from, signature)`)
   → a byte-valid `budget_limit` record (§4).
2. **Sign** it with Delta's key (§5) → the compact-JWS `signature` + `policy_hash`.
3. Insert a **`budget_publish_outbox`** row carrying the **signed record** (jsonb), state
   `pending`. This row is the **durable enforcement decision** — committing it atomically with
   the state flip is what guarantees a decision is never lost even if the process dies before
   the network call (vector 11).

A **drainer** then POSTs pending rows to the **real O-004 seam**:
`POST /v1/policies/distributions` `{policy: <signed>, sign_on_behalf: false}` with
`Authorization: Bearer ORCH_SERVICE_TOKEN`. On `202` → record `distribution_id`, state
`distributed`. The drainer runs **best-effort inline** right after the outbox commit (for
sub-second latency, §10) **and** as a retry sweep (for durability). Either way the decision is
already durable in the outbox before any network call.

### 3.5 Fail posture (Fork 4) — the two dangerous directions

- **EVAL failure (ledger read fails) → fail-SAFE, never wrongly enforce.** A transient read
  error must NEVER cause an enforcement publish (never cut off an under-budget tenant on a
  blip). Transient classification matches D-004 `is_transient` and the F-007-FU lesson — it
  **must include** `OSError` (a down DB raises `ConnectionRefusedError`),
  `sqlalchemy.exc.TimeoutError`, `OperationalError`, `InterfaceError` — not just
  `OperationalError`. On transient: bounded retry + a loud alert/metric; the ingest still
  returns 200 (the debit is durable). A persistent eval failure is a **monitored incident**
  (alert), never a silent gap. A non-transient logic error is logged loudly and never silently
  swallowed into a fail-open.
- **PUBLISH failure (O-004 down / non-2xx / missing signing key) → never silently drop.** The
  decision is already durable in the outbox (`pending`). The drainer retries with bounded
  backoff up to `max_attempts`; on exhaustion the row goes `failed` (the **dead-letter** — the
  outbox doubles as the DLQ, mirroring D-004) **with a loud alert**. A dropped decision = spend
  runs past the cap, so this path is fail-LOUD, never fail-quiet. **A missing/invalid signing
  key is a config error treated as a publish failure** (decision recorded in the outbox + alert)
  — it is NOT a fail-open (nothing un-enforced is published) and NOT a silent drop.

**Invariant.** Neither failure may (i) wrongly enforce an under-budget tenant, nor (ii) silently
lose a real enforcement decision.

### 3.6 Advisory warnings (CONFIRM B)

Soft-threshold warnings (D-002 `BudgetWarningTier`) emit alert events/log lines only. They share
**no code path** with publish; a warning can never write an outbox row or flip enforcement state
(vector 10).

---

## 4. Byte-valid proof (the central artifact)

The published policy MUST validate against the **UNMODIFIED** locked
`Anoryx-Sentinel/contracts/policy.schema.json` (`$id sentinel:policy:v1`, "LOCKED at F-008
a9e2344"), and `policy_type` MUST stay `budget_limit` (already present in both the schema
`oneOf` and Sentinel's runtime `_VALID_POLICY_TYPES`). **D-005 does not edit the schema and does
not add a policy_type (CRIT-2).**

- **Vehicle:** the D-002 emit path already produces a `budget_limit` record proven byte-valid by
  `Delta/tests/test_budget_policy_emit.py`, which loads the real locked schema (asserting
  `$id == "sentinel:policy:v1"` and `"LOCKED at F-008"`) and validates with a Draft-2020-12
  validator. D-005 reuses this path unchanged.
- **D-005 adds two guards:**
  1. a test that `git diff` of `Anoryx-Sentinel/contracts/policy.schema.json` is EMPTY after the
     whole feature (the lock is byte-untouched);
  2. the non-stubbed e2e (§10) asserts the **real** O-004 schema validation accepts the policy
     AND the **real** Sentinel `intake_policy()` accepts the signature.

---

## 5. Signing & distribution boundary (who signs, who distributes)

- **Delta signs.** D-005 vendors a byte-identical signer (`delta/policy/sign.py`) reproducing
  Sentinel's canonicalization exactly: payload = the 8 `SIGNED_CLAIM_FIELDS`
  (`tenant_id, team_id, project_id, agent_id, policy_id, policy_version, effective_from,
  policy_type`) + `policy_hash` (SHA-256 of the canonical record), header `{"alg":"ES256",
  "typ":"JWT"}`, payload `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True)`,
  ECDSA P-256 with raw R‖S signature (NOT DER, NOT JCS — ADR-0009 §12.1). A **conformance test**
  imports Sentinel's `policy.crypto` (test-only dependency) and asserts byte-for-byte equality
  of `delta.policy.sign` output vs `crypto.sign_policy_record` on sample records, so the vendored
  copy can never silently drift from the verifier.
- **Key custody.** A P-256 PKCS#8 PEM **private** key, injected via env
  `DELTA_POLICY_SIGNING_PRIVATE_KEY_PEM`, loaded **fail-closed** (absent/empty/non-P256 →
  raise; mirrors R-003 `Rendly/src/rendly/auth/keys.py`). Delta's SPKI **public** key is
  installed at Sentinel's `POLICY_SIGNING_PUBKEY_PATH`. Production HSM/KMS + rotation are
  deferred (ADR-0009 §12) — out of D-005 scope.
- **O-004 distributes, does not sign** (ADR-0004 Fork A). D-005 sends `sign_on_behalf:false`
  and never asks O-004 to sign. O-004 validates the policy against the locked schema, forwards
  the signed record byte-identical to Sentinel, and reports `distributed`/`failed` (vector 9).

---

## 6. Tenant isolation

Tenant A's overage can NEVER enforce on tenant B:

- All three D-005 tables are RLS `ENABLE + FORCE` under `delta_app` (NOBYPASSRLS) with the strict
  fail-closed predicate `tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')`
  (USING + WITH CHECK), identical to D-003 (vectors 1, 2). An unset/empty GUC collapses to zero
  rows, never a widen.
- The published policy's scope IDs come from the **budget definition** (server-side config),
  never from request input; the signer binds them into the JWS; Sentinel re-derives authoritative
  scope from the **verified claims** and rejects wildcard-tenant + any body/claim scope mismatch.
  A tampered scope cannot widen reach (vectors 7, 8).

---

## 7. Data model (migration 0003, down_revision "0002")

Three tables in the `delta` schema, RLS-scoped to `delta_app`, **reversible** (the
`migration-roundtrip` CI job proves upgrade→downgrade→upgrade + drop-schema rebuild). Unlike the
append-only ledger, these are **mutable-within-tenant** (state transitions, delivery status), so
`delta_app` is granted `SELECT, INSERT, UPDATE` (no DELETE) and RLS allows tenant SELECT/INSERT/
UPDATE.

- **`budget_definitions`** — the caps to evaluate: `budget_id` PK, `tenant_id`, `scope`,
  `team_id`/`project_id`/`agent_id`, `period`, `limit_tokens` (nullable), `limit_cost_cents`
  (nullable, BIGINT), `policy_id` (stable), `currency`, `created_at`. (Budgets seeded via an
  internal create path — function/CLI; the full allocation UI is D-007.) `CHECK` mirrors the
  schema `anyOf` (at least one limit).
- **`budget_enforcement_state`** — edge state: the scope key columns + `period_bucket`,
  `state ('under'|'enforced')`, `enforced_policy_version BIGINT`, `last_published_version BIGINT`,
  `updated_at`; partial UNIQUE on the scope key + period_bucket.
- **`budget_publish_outbox`** — durable decision + delivery: `outbox_id` PK, `tenant_id`,
  `budget_id`, `policy_id`, `policy_version`, `signed_policy JSONB`, `distribution_id` (nullable),
  `state ('pending'|'distributed'|'failed')`, `attempts`, `next_attempt_at`, `last_error`,
  `created_at`. The `failed` state is the dead-letter. The `signed_policy` content is immutable
  once written (the decision); only delivery columns mutate. Migrations carry the `S608`
  per-file-ignore already configured in `pyproject.toml`.

---

## 8. Honesty boundary (what D-005 is NOT)

- **Delta-side enforcement loop only.** D-005 proves the publish reaches the **real O-004 seam**
  (`distributed`) and that the signed policy is accepted by the **real** Sentinel
  `intake_policy()` (via the same test shim O-004's own e2e uses, because the Sentinel HTTP
  intake route does not exist in prod). **The live gateway allow→deny (full
  Delta→Orchestrator→Sentinel compose) is X-003**, not claimed here.
- **NOT in scope:** the kill-switch (D-006 — a separate, faster emergency brake for unauthorized
  agent txns), the budget allocation UI (D-007), dashboards (D-008), the full 3-product e2e
  (X-003). Honest language per the root CLAUDE.md: "client-side cost estimate", "audit-ready".

---

## 9. Threat model (12 vectors → test paths)

| # | Vector | Mitigation | Test |
|---|---|---|---|
| 1 | Cross-tenant enforcement-state read/write | RLS FORCE + NULLIF predicate on all 3 tables | `test_state_rls_isolation` |
| 2 | Unset/empty GUC widens rows | NULLIF → zero rows; `get_tenant_session` fail-closed | `test_state_unset_guc_zero_rows` |
| 3 | Stale-spend decision (eval on a pre-commit snapshot) | eval runs post-commit, fresh tenant txn; spend SUM on its own snapshot | `test_eval_sees_committed_debit` |
| 4 | Float-boundary flip of the cap comparison | integer cents only; `used > cap` integer compare; no float in path | `test_no_float_boundary` |
| 5 | Race / double-publish on concurrent appends crossing the cap | conditional `UPDATE ... WHERE state='under'`; rowcount gates publish | `test_concurrent_cross_one_publish` |
| 6 | Enforce/un-enforce flapping; stuck-blocked tenant | edge state + monotonic version; over→under publishes refreshed higher cap | `test_raise_lifts_enforcement` |
| 7 | Wrong-scope publish | scope IDs from server-side budget def; signed into JWS | `test_published_scope_matches_budget` |
| 8 | Cross-tenant enforcement (A overage → B blocked) | RLS + per-tenant scope binding; B never evaluated by A's event | `test_tenant_a_overage_not_enforce_b` |
| 9 | Signing-boundary violation (unsigned / O-004-signs) | Delta signs; `sign_on_behalf:false`; real intake accepts | `test_signed_policy_accepted_by_real_intake` |
| 10 | Warning-as-enforcement (soft warning hard-blocks) | warnings share no publish path; never write outbox | `test_warning_never_publishes` |
| 11 | Fail-open on publish (O-004 down → decision dropped) | transactional outbox; retry; `failed`+alert, never dropped | `test_o004_down_decision_not_lost` |
| 12 | Fail-closed-wrong on transient eval error (blip → wrongly enforce) | transient classify (incl OSError/TimeoutError) → no publish | `test_transient_eval_no_false_enforce` |

---

## 10. Sub-second Delta-leg SLA + measurement

**Delta-leg latency = cap-cross detected (post-commit eval) → O-004 returns 202** for the
published policy. Measured with a monotonic clock around `evaluate → sign → POST` in the
non-stubbed integration test; target **< 1s**. The decision write (state flip + outbox) is all
local DB; signing is a single ECDSA op; the inline drainer POST is the only network hop. The
full gateway block latency is X-003 and not measured here.

---

## 11. Rollback & reversibility

- Migration 0003 `downgrade()` drops the 3 tables, their policies, and grants in reverse order;
  it retains the `delta` schema (houses `alembic_version`) and never touches ledger/tenant data.
  The `migration-roundtrip` CI job proves up→down→up + a true drop-schema rebuild.
- Operational off-switch: `DELTA_BUDGET_ENGINE_ENABLED` (default on). With it off, evaluation is
  skipped (no publish); existing distributed policies remain in Sentinel until their period
  resets or a refreshed cap is published. With no `budget_definitions` configured the engine is
  inert regardless. (This is operational hygiene, NOT the D-006 kill-switch.)

---

## 12. Consequences

- **Positive:** the killer-feature loop is real on the Delta leg — ledger-authoritative spend
  autonomously arms F-008 enforcement, byte-valid against the locked contract, with no schema
  change and proven failure posture in both dangerous directions.
- **Negative / accepted:** D-005 owns a Delta signing identity (new key custody surface, HSM
  deferred); enforcement accuracy at the Sentinel leg depends on F-008's own F-006 spend counter
  converging with Delta's ledger (same underlying events; ingest lag is in the safe direction);
  the live gateway block is unproven until X-003.
- **Deferred (review LOW):** the drainer is invoked event-driven (per inbound usage event for
  the tenant) — a decision that fails to publish while the tenant then goes idle is retried only
  on the tenant's next event. It is never lost (durable outbox + dead-letter alert) and idle
  tenants do not accrue spend, so exposure is bounded; a periodic background sweep + a
  pending/failed-outbox-depth liveness metric are an ops/monitoring follow-up (D-008).
