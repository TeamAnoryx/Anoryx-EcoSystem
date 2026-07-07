# D-006 Kill-Switch — Independent Security Audit (arms-length red-team)

- Auditor: Anoryx Sentinel Security Auditor (independent; did not write this code)
- Date: 2026-07-07
- Scope: `Delta/src/delta/kill_switch/*`, migration `0004_kill_switch.py`, `persistence/models.py` additions, `ingest/{app,router}.py` wiring, ADR-0006, `tests/kill_switch/*`. Reused D-005 seams (`policy/sign.py`, `budget_engine/publisher.py`, `budget_engine/{state,outbox,drainer}.py`) reviewed for context/comparison only — not re-flagged, since they are prior, already-audited D-005 code D-006 reuses unchanged.
- Method: full threat-model of both catastrophic directions (FALSE kill / MISSED kill), manual data-flow trace, contract-lock diff, manual taint scan (Semgrep itself could not reach its registry from this sandbox — network-restricted; the ruleset download failed with a proxy 403. CI has real network access and should run it as a follow-up gate, same command as the D-005 audit: `semgrep scan --config=p/python --config=p/security-audit --config=p/secrets --severity=ERROR`).

## Verdict: CLEAN (no High/Critical) — one Medium, four Low findings, all fixed

## Contract-lock verification (PASS)

- `git diff origin/main -- Anoryx-Sentinel/contracts/policy.schema.json` = EMPTY (lock untouched).
- Kill/clear payloads built by the unchanged D-002 `budget_concept_to_policy_payload`; `policy_type` stays `budget_limit`. `tests/kill_switch/test_emit.py` validates both against the REAL locked schema file (asserts `$id == "sentinel:policy:v1"` and `"LOCKED at F-008"` in the raw bytes — not tautological).
- No secret/key/token literal in source; the kill-switch reuses the D-005 signer/publisher verbatim (no new key custody surface).

## What is sound (verified, not taken on faith)

- The D-005 H-1 defect (cross-period `policy_version` reset) does NOT recur here: `kill_switch_state` has no period bucket — one row per scope for its lifetime — so `last_published_version` is monotonic for that row's entire life and the outbox `UNIQUE(tenant,policy_id,version)` can never silently no-op a real decision.
- The conditional `UPDATE ... WHERE state='clear'` (kill) and `WHERE state='killed'` (clear) are exercised by genuine concurrency tests using `asyncio.gather` against a live Postgres (`test_concurrent_offense_exactly_one_winner`, `test_concurrent_authorize_agent_clears_a_scope_exactly_once`), not sequential stand-ins.
- RLS FORCE + the strict NULLIF predicate on all three new tables, plus the empty-GUC-sees-zero-rows path, are real-DB tested (`test_state_rls_isolation`, `test_unset_guc_sees_zero_state_rows`, `test_authorizations_rls_isolation`).
- `policy_id` is independently minted per kill-switch scope (own `uuid4`, own table) — asserted `!=` a D-005 budget's `policy_id` for the identical scope (`test_kill_switch_policy_id_space_independent_of_budget_definitions`); the two enforcement layers can never collide or overwrite each other, and F-008's `evaluate_budget_against` composes multiple `budget_limit` policy_ids per scope with AND semantics, so a kill and a real budget cap coexist correctly.
- `bounded_count` (money.py) accepts `0`, so the zero-cap kill payload is not silently rejected at construction.
- Transient detection-read errors never publish a kill (`test_transient_detect_error_no_false_kill` forces `ConnectionRefusedError` mid-evaluation); non-transient errors are swallowed loud, never fail-open.
- Publish failures are never silently dropped: durable outbox before any network call, bounded retry/backoff, dead-letter + loud alert on exhaustion or a missing signing key — identical fail posture to D-005, proven by DB tests forcing each failure mode.

## Findings (all addressed post-review)

### M-1 (Medium → FIXED) — Un-kill enqueued the unblocking decision but never delivered it

Files: `kill_switch/authorizations.py` (`authorize_agent`, `clear_kill_switch`, pre-fix).

The ADR's headline claim ("does not wait for a new inbound event") was not actually implemented: `authorize_agent`/`clear_kill_switch` only insert the outbox row inside the caller's transaction; nothing drains it. `evaluator.py`'s kill path auto-drains after every kill, but the un-kill path had no equivalent. If the (future) admin caller committed without a paired `drain_tenant` call — or died between commit and drain — a killed scope with no other tenant traffic would sit `pending` forever: no delivery attempt, therefore no retry, no dead-letter, no alert. A legitimately re-authorized agent would stay hard-blocked with no alarm.

**Fix:** added `authorize_agent_and_publish()` / `clear_kill_switch_and_publish()` — the real entry points, which open the tenant session, run the DB-only primitive, commit, and immediately call `drain_tenant` in the same call. New tests `test_authorize_and_publish_delivers_without_a_new_event` and `test_clear_kill_switch_and_publish_delivers_without_a_new_event` assert delivery happens with NO separate drain call. ADR-0006 §3.6/§2 fork 5 and the threat table (new vector 11) updated.

### M-2 (Medium → FIXED) — Allow-listing an agent silently also lifted an unrelated anomaly kill

File: `kill_switch/authorizations.py:90` (pre-fix), `kill_switch/state.py` (`killed_scopes_for_agent`).

`killed_scopes_for_agent` filtered only `state='killed'`, ignoring `reason`, so `authorize_agent` (which remedies `unauthorized_agent`) also cleared that same agent's `anomalous_single_tx` kills — a trigger the identity allow-list has no authority over. An agent killed for both a genuinely oversized transaction AND an unrelated identity issue would have its anomaly block silently lifted the moment an operator fixed the identity issue, for a reason unrelated to the anomaly review.

**Fix:** `killed_scopes_for_agent` takes an optional `reason` filter; `authorize_agent` now passes `reason=UNAUTHORIZED_AGENT`, so it only ever clears kills it caused. `clear_kill_switch` (the explicit, unscoped operator override) is unaffected — it remains the correct tool for lifting an anomaly kill. New test `test_authorize_does_not_clear_anomalous_kill` asserts an anomaly kill survives an `authorize_agent` call for the same agent.

### L-3 (Low → DOCUMENTED, deferred) — No background sweep; an idle scope's OTHER pending decisions wait for its next event

Same shape as ADR-0005's own L-1 (accepted/deferred). `evaluate_kill_switch` only drains inline, per event; a kill self-heals (the still-unblocked rogue keeps sending events, each re-draining), and the new `_and_publish` entry points self-drain for the un-kill path (M-1 fix), but any OTHER decision for a since-gone-idle tenant still waits for its next event or a future periodic sweep. Bounded and durable (dead-letter + alert on exhaustion), never silently lost.

**Resolution:** documented in ADR-0006 §8 as the same accepted, bounded limitation ADR-0005 §12 already deferred to ops/D-008 (a periodic sweep + pending/failed-outbox-depth liveness metric). Not implemented here — out of D-006's scope, matching the D-005 precedent.

### L-4 (Low → FIXED, documentation) — ADR wording implied a per-tenant anomaly ceiling; the implementation is deployment-wide

File: ADR-0006 (pre-fix wording), `kill_switch/config.py` (`max_single_tx_cost_cents`, unchanged — this was a documentation defect, not a code defect).

`DELTA_KILL_SWITCH_MAX_TX_COST_CENTS` is a single deployment-wide env var applied identically to every tenant (`evaluator.py` passes the same `settings` to every tenant's evaluation) — there is no per-tenant override, unlike the genuinely per-tenant `agent_authorizations` allow-list. The ADR's original §2/§7 framing ("opt-in ... never a silent new restriction on an existing tenant") could be misread as per-tenant opt-in, which it is not: a deployment that sets the ceiling imposes it on ALL tenants, including ones with legitimately large one-off transactions.

**Fix:** ADR-0006 §7/§8 corrected to state plainly that the ceiling is deployment-wide, not per-tenant, and that a genuinely per-tenant ceiling is a natural (unbuilt) follow-on. No code change — honest-language correction only (per root `CLAUDE.md`).

### L-5 (Low → FIXED) — `clear_kill_switch` created a spurious state row on a mistyped/never-seen scope

File: `kill_switch/authorizations.py:117` (pre-fix, used `get_or_create_state`).

An operator override for a scope that was never actually killed (e.g. a typo in team/project/agent) would INSERT a fresh `clear`-state row with a newly minted `policy_id` before returning `False` — harmless (never published, RLS-scoped), but a cardinality/audit-cleanliness leak, and it burns a `policy_id` that never corresponds to any real kill.

**Fix:** added a read-only `state.find_state()` (no insert); `clear_kill_switch` now uses it instead of `get_or_create_state`. `test_clear_kill_switch_on_a_never_killed_scope_is_a_noop` strengthened to assert `SELECT count(*) FROM delta.kill_switch_state` is `0` after the no-op call.

## Probe checklist

- Reversal / spend derivation: N/A — the kill-switch has no spend accumulation (its whole point is to react per-transaction, not per-period).
- Float anywhere in the trigger/emit path: PASS — integer cents throughout (`triggers.anomalous_reason`, `emit.build_kill_payload`/`build_clear_payload`).
- Transient detect error → false kill: PASS — never publishes (vector 3).
- Outbox durable before network call: PASS — committed pre-drain, identical pattern to D-005.
- Un-kill delivered without a new event: FAIL pre-fix (M-1) → PASS post-fix.
- Allow-list clear over-reaches to an unrelated kill reason: FAIL pre-fix (M-2) → PASS post-fix.
- Cross-tenant A-to-B kill: PASS — RLS FORCE + server-side scope binding, tested live.
- Race/double-kill, double-clear: PASS — conditional UPDATE + outbox UNIQUE (one winner), tested with real concurrency.
- Byte-valid vs locked schema / no new `policy_type`: PASS — empty schema diff; real-schema validator test.
- `policy_id` collision with a D-005 budget: PASS — independently minted, asserted distinct.
- Spurious state row on a bad operator input: FAIL pre-fix (L-5) → PASS post-fix.
- Fail-open on O-004-down / missing signing key: PASS — durable + retry + DLQ, reuses D-005's proven drainer logic unchanged.

## Recommendation

Merge. All Medium/Low findings from this pass are fixed or explicitly, honestly deferred (L-3, matching the accepted D-005 precedent). Re-run Semgrep in CI (network-unrestricted) as a confirming gate; this sandbox could not reach the rule registry.
