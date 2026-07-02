# D-005 Budget Engine — Independent Security Audit (arms-length red-team)

- Auditor: Anoryx Sentinel Security Auditor (independent; did not write this code)
- Date: 2026-07-01
- Scope: Delta/src/delta/{policy/sign.py, budget_engine/*, ingest/{app,router}.py, persistence/models.py}, migration 0003_budget_engine.py, ADR-0005, tests/budget_engine/*.
- Method: full threat-model of both catastrophic directions (FALSE / MISSED enforcement), manual data-flow trace, contract-lock diff, Semgrep on the changed surface.

## Verdict: BLOCK

One High missed-enforcement defect (cross-period policy-version reset) -> human escalation required. No retry overrides this. Three Low defense-in-depth / documentation items. This is no High/Critical findings in this pass only AFTER H-1 is fixed.

## Contract-lock verification (PASS)

- git diff origin/main -- Anoryx-Sentinel/contracts/policy.schema.json = EMPTY (lock untouched).
- git diff origin/main -- Anoryx-Sentinel/src/persistence/repositories/policy_repository.py = EMPTY (_VALID_POLICY_TYPES already contains budget_limit; no new policy_type).
- Published payload built by the unchanged D-002 budget_concept_to_policy_payload; policy_type stays budget_limit. Conformance test asserts the Delta signer is byte-identical to Sentinel policy.crypto (header, canonical_claims incl. non-ASCII uXXXX escaping, policy_content_hash, extract_claims, SIGNED_CLAIM_FIELDS/CONTENT_HASH_CLAIM) and that a Delta signature verifies through Sentinel real verify_compact_jws. Wildcard-tenant signing is refused.
- Semgrep (p/python, p/security-audit, p/secrets, severity ERROR) on the D-005 surface: 0 results, 0 errors.
- No secret/key/token literal in source; signer/publisher/config never log key, token, or signature.

## What is sound (verified, not taken on faith)

- Reversal net = 0 (no false inflation): D-004 posts DEBIT expense / CREDIT liability-contra (resolver.py contra = AccountType.LIABILITY); reverse_transaction swaps direction on the same accounts -> CREDIT expense / DEBIT liability. scope_spend_cents nets debit-credit and filters accounts.type = expense, so the contra legs are excluded and a reversal nets to 0. The only DEBIT to an expense account is the original usage; nothing else inflates the expense-net.
- No float in the spend-vs-cap path: BIGINT cents end-to-end; is_over_cost_cap is integer strict greater-than; soft_warning_band uses integer spend*100 vs pct*cap. SUM(bigint) returns numeric -> int(Decimal) is exact.
- Fresh, not stale, spend: eval is a post-commit side-effect on a NEW tenant session opened after post_usage committed; the read includes the just-committed debit. Idempotent replays re-evaluate without adding a second debit.
- Strict over-cap boundary: spend == cap is within budget; only spend greater-than cap enforces (matches F-008). No off-by-one false enforcement.
- Transient eval error never enforces (vector 12): both is_transient and the non-transient branch only log; neither publishes. is_transient includes OSError/ConnectionRefusedError/SATimeoutError (ADR-0026 lesson).
- Decision durable before any network call (vector 11): state flip + outbox insert commit in one txn before drain_tenant. Publish failure -> retry/backoff -> failed DLQ + loud alert; missing signing key -> all rows stay pending + alert (never fail-open, never silent drop). Per-row drain in its own txn (FOR UPDATE SKIP LOCKED).
- Tenant isolation: RLS ENABLE+FORCE on all 3 tables under delta_app (NOBYPASSRLS), strict NULLIF predicate (USING+WITH CHECK), no DELETE grant/policy. tenant_id is taken from the HMAC-authenticated event and set as the transaction-local GUC; budgets/spend/state/outbox are all RLS-confined. Published scope IDs come from the server-side budget definition, not request input; signer refuses wildcard tenant. Cross-tenant A-to-B enforcement is structurally impossible.
- One-winner concurrency: conditional UPDATE WHERE state = under rowcount gates publish; outbox UNIQUE(tenant,policy_id,version) is defense-in-depth. Verified by the e2e exactly-one-202.
- Warnings cannot block: warnings.py shares no path with the outbox/state; advisory log only.
- Migration reversible: downgrade drops policies/grants/indexes/tables in dependency order, retains the delta schema; no DELETE grant.
- No SSRF / injection: distribution URL is deployment config (not request-derived); httpx default TLS verify; all queries are parameterized SQLAlchemy core; DDL f-strings use internal constants only.

## Findings

### H-1 (High -> BLOCK) — Cross-period policy_version reset silently drops enforcement in every period after the first

Files:
- src/delta/budget_engine/state.py:51-88 (get_or_create_state inserts last_published_version = 0 for each new (tenant_id, budget_id, period_bucket))
- state.py:107 (new_version = last_published_version + 1)
- src/delta/budget_engine/outbox.py:65-67 (on_conflict_do_nothing on (tenant_id, policy_id, policy_version))
- migration 0003_budget_engine.py:163 (last_published_version server_default 0), :158 (period_bucket is part of the uniqueness key)
- cross-checked against Sentinel policy_repository.py:95-106,190-202 (replay max is per policy_id, GLOBAL — no period dimension; the 0004 DB trigger likewise)

Defect. The enforcement-state row, and therefore the monotonic last_published_version counter, is keyed by period_bucket, so it resets to 0 every period. But policy_id is stable per budget across all periods, and BOTH Sentinel replay protection AND the D-005 outbox UNIQUE are keyed on (policy_id, version) GLOBALLY. So in any period after the first, the first under-to-over crossing computes policy_version = 1, a value already used in period 1.

Exploit / failure path (concrete, reachable via normal ops):
1. June (monthly budget, cap 100): tenant crosses -> state row (bucket June) flips under-to-enforced, version 1, outbox row (tenant,policy_id,1) enqueued and distributed. Sentinel enforces.
2. July: a usage event creates a NEW state row (bucket July), last_published_version 0, state under. Tenant crosses the cap -> conditional UPDATE succeeds (the July row IS under) -> returns version = 0+1 = 1. enqueue_decision then INSERTs (tenant,policy_id,1) which conflicts with the June row -> on_conflict_do_nothing makes it a no-op. No pending row is created; drain_tenant has nothing to send; NO policy is published. Yet the evaluator logs delta.budget ENFORCE decided version=1 and the state row now claims enforced_policy_version=1, a record of an enforcement that was never delivered.
3. Even if it were delivered, Sentinel rejects version 1 as a replay (1 less-than-or-equal current_max).

Steady-state masking is fragile: enforcement in July only happens if F-008 still holds the June policy and re-applies it with a reset counter, an untested cross-system assumption. It breaks outright when the cap is LOWERED for the new period (Sentinel keeps the stale higher cap; the new lower cap is never enforced) or when the budget was RAISED/refreshed in the prior period (current_max advanced; the new period can never publish an accepted version, and the Sentinel live policy is the raised cap). For DAILY budgets it fires every day after any raise. Net effect: spend runs over the cap with no Delta-published enforcement, and the Delta logs/state/outbox falsely report success, defeating both the guardrail and its audit trail. This is exactly catastrophic direction 2 (MISSED enforcement, silently dropped): the on_conflict_do_nothing no-op produces no error, no alert, and no pending row.

Why not Critical: in the narrow no-cap-change case, F-008 per-period reuse of the period-1 live policy may still block the scope, so the most benign deployment is partially masked. It trends to Critical for any deployment that ever changes a cap between periods.

Fix. Make the published version a monotonic counter per (tenant_id, policy_id), not per period_bucket. Options: (a) when creating a new period state row, seed last_published_version from MAX(last_published_version) over all buckets of that (tenant_id, budget_id), or from MAX(policy_version) in budget_publish_outbox for that (tenant_id, policy_id), instead of 0; or (b) hold the version counter on budget_definitions (one per policy_id) and keep period_bucket only for the under/enforced edge state. Add a cross-period regression test: enforce in bucket P1, advance now into P2, cross again, assert a NEW outbox row with policy_version greater-than P1 is enqueued AND distributed, and that a refresh in P1 followed by an enforce in P2 still produces a strictly-increasing, accepted version.

### L-1 (Low) — No background drainer: a pending decision for an idle tenant is delivered only on its next event

File: src/delta/budget_engine/evaluator.py:88 (drain is invoked only from evaluate_after_post, i.e. per inbound usage event for that tenant).
Scenario: tenant crosses the cap, the single inline publish hits a transient O-004 failure (mark_retry, still pending), then the tenant stops sending events. Nothing re-drains that tenant until it sends another event, so distribution is deferred indefinitely with only a per-attempt warning log (no dead-letter, no alert) until retries exhaust. Not a silent loss (durable + alert on dead-letter), and financial exposure is bounded (an idle tenant is not spending; at most about one event leaks when traffic resumes, after which the resume event re-drains).
Fix: add a periodic background sweep, or a liveness metric on pending/failed outbox depth + oldest next_attempt_at, so delivery does not depend on continued tenant traffic.

### L-2 (Low) — Stale spec describes the pre-review (buggy) spend formula

Files: ADR-0005 section 3.1 (shows SUM over debit-only with timestamp less-than now) and src/delta/budget_engine/periods.py:1-6 module docstring (window [period_start, now)).
The shipped code is the corrected version (net debit-credit over type = expense; window [period_start, period_end)). The stale docs describe the exact bug a prior review fixed (reversal over-counting and the now upper bound), and could lead a future maintainer to restore it. Update both to match spend.py.

### L-3 (Low) — scope_spend_cents ignores currency

File: src/delta/budget_engine/spend.py:57-82 (no accounts.currency filter; the budget currency is unused in the spend query).
Today Delta is single-currency (DEFAULT_CURRENCY forced in posting.py), so there is one expense account per tenant and no exploit. But a budget seeded with a non-default currency, or any future multi-currency posting, would compare or aggregate minor units across currencies with no guard. Defense-in-depth: filter accounts.c.currency == budget.currency, and/or reject a budget whose currency does not match the ledger currency at create time.

## Probe checklist

- Reversal net truly 0 / partial / multiple / foreign credits: PASS — expense-only net; only usage debits expense; reversals credit expense; multiples under-count (safe direction).
- Float anywhere in spend-vs-cap: PASS — integer cents throughout.
- Stale spend: PASS — post-commit fresh session.
- Over-cap boundary (strict vs non-strict): PASS — strict greater-than, matches F-008.
- Transient eval error -> enforce: PASS — never publishes (vector 12).
- Outbox durable before network call: PASS — committed pre-drain.
- Decided-then-publish-fails: PASS — retry/backoff/DLQ + alert.
- Exception swallowing drops a decision: FAIL (H-1) — on_conflict_do_nothing silently drops the cross-period re-enforcement.
- Missing-key path: PASS — stays pending + alert, not fail-open.
- Per-row drain lost/stuck: PASS — SKIP LOCKED, own txn, bounded backoff; see L-1 for idle-tenant latency.
- Cross-tenant A-to-B enforcement: PASS — RLS FORCE + server-side scope binding.
- Race/double-publish: PASS — conditional UPDATE + outbox UNIQUE (one winner).
- Byte-valid vs locked schema / no new policy_type: PASS — empty schema diff; conformance test.
- Warnings cannot hard-block: PASS — no shared path.
- Budget-raise lifts enforcement: PASS within a period; subject to H-1 across periods.
- Fail-open on O-004-down: PASS — durable + retry + DLQ.
- Scope tamper / wildcard widening: PASS — server-side scope; wildcard tenant refused.
- Signer canonicalization vs Sentinel: PASS — conformance test.
- RLS FORCE + grants (no DELETE) + reversible migration: PASS.

## Recommendation

Fix H-1 (cross-period monotonic versioning) and add the cross-period regression test before merge. Address L-1/L-2/L-3 in the same pass or as immediate follow-ups. Re-audit after H-1 fix.

---

## Builder resolution (post-audit, re-verified)

The auditor's BLOCK verdict + findings above are the record. All four findings are resolved;
the budget_engine suite re-ran **99 passed, 0 failed** (incl. a new cross-period regression test).

- **H-1 (High → FIXED):** `state.get_or_create_state` now seeds a new period's
  `last_published_version` from the GLOBAL max over all prior buckets of that (tenant, budget)
  via a scalar subquery — `policy_version` is monotonic per `policy_id` globally, never reset to
  0 per period. New test `test_version_monotonic_across_periods` asserts period-2's first
  crossing yields version 2 (not a re-used 1 that would silently no-op the outbox INSERT).
  ADR §3.1 documents the invariant.
- **L-1 (Low → DOCUMENTED):** the event-driven-only drainer + the "add a background sweep +
  pending/failed-outbox-depth metric" follow-up are recorded in ADR §12 as a bounded,
  never-lost limitation deferred to ops/D-008.
- **L-2 (Low → FIXED):** `periods.py` module docstring and ADR §3.1 updated to the shipped
  formula (net debit−credit over `type='expense'`, half-open `[period_start, period_end)`).
- **L-3 (Low → FIXED):** `scope_spend_cents` now filters `accounts.currency = <budget currency>`
  so minor units are never aggregated across currencies.

Auditor-confirmed clean (unchanged by the fixes): locked `policy.schema.json` + `policy_repository.py`
EMPTY diffs vs origin/main; semgrep 0 on the D-005 surface; vendored signer byte-conformant;
reversal nets to zero (contra is LIABILITY); tenant isolation = RLS FORCE + server-side scope binding.
