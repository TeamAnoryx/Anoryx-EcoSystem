# F-017 JSON Data-Lock Engine â€” Independent Security Audit (arms-length red-team)

- Feature: F-017 â€” 6th PostResponseHook (src/data_lock/); conditional field-level withholding of locked fields in assistant JSON output. FAIL-CLOSED.
- ADR: docs/adr/0020-json-data-lock-engine.md (Proposed)
- Branch: task/F-017-... (migration head 0023)
- Auditor posture: independent; did NOT write this code; no benefit of the doubt; actively tried to break it.
- Date: 2026-06-23

## VERDICT: PASS

No High or Critical findings in this pass. The fail-open leak risk (the headline risk for a data-lock per ADR section 2 / R1) was attacked along every error/timeout/exception path and no path was found that returns an un-withheld body. Caller-forgeable unlock was attacked via header/body/model-output claims and is not reachable (conditions read only server-resolved ctx.tenant_context + server clock). CRIT-2 (the F-016 inert-feature trap) is genuinely closed and proven by non-stubbed DB tests run by the auditor. Findings below are Low/Med correctness + contract-divergence defects that are all fail-CLOSED â€” they can only block a tenant's own responses, never leak a locked field.

## Empirical verification (run by the auditor, not trusted from the brief)

- tests/data_lock â€” 75 passed (PYTHONPATH=src SENTINEL_PROVISION_APP_ROLE=1).
- Non-stubbed CRIT-2 persist (test_crit2_policy_persist.py) + non-stubbed e2e (test_e2e_nonstubbed.py) â€” 3 passed, run explicitly. The e2e proves: real upsert_policy('data_lock') -> real get_tenant_session RLS load -> real gateway -> real run_data_lock hook -> result.ssn ACTUALLY replaced with [withheld:data-lock] while the unmatched result.name is untouched, and a real field_locked audit row is written under the caller's real tenant. Only orthogonal mocks (upstream LLM provider, F-008 Redis enforce, F-006 routing) â€” ZERO stubs on config/load/persist/enforcement.
- tests/persistence/test_migrations.py â€” head-pin is 0023; reversible downgrade->upgrade round-trip passes.
- Full suite â€” 1329 passed, 0 failed.
- ruff check (8 changed files) â€” No issues. black --check â€” all unchanged.
- semgrep scan --config=p/python --config=p/security-audit --config=p/secrets --severity=ERROR over src/data_lock, registry.py, chat_completions.py, policy_repository.py, policy.py, events_audit_log.py, migrations 0022/0023 â€” 0 ERROR findings.

## Attack 1 â€” FAIL-OPEN leak on error (the headline risk). RESULT: not reachable.

Traced every error/timeout/exception path for one that RELEASES a locked field:

- config.load_data_lock_config RAISES DataLockConfigError on empty/blank tenant_id, session error, query error, multi-active-policy, unparseable payload, malformed rule (src/data_lock/config.py:69-104). This is the deliberate inversion of F-016 swallow-to-disabled. Detector catches it -> _block_error -> action="block" (src/data_lock/detector.py:70-74).
- detector.inspect: envelope unparseable -> block (:82-85); content over MAX_CONTENT_BYTES (256 KiB) while armed -> block (:105-107); SelectorBudgetError -> block (:117-119). An UNEXPECTED exception from evaluate/apply_withhold propagates out of inspect -> HookRegistry._run_hook wraps it as HookFailSafeError (registry.py:354-362) -> run_data_lock re-raises -> gateway -> GatewayError("internal_error") 500. No body returned on any branch.
- _apply_rules (detector.py:159-220): Pass 1 (UNMET rules) does the real withholding first on a shared budget; a budget breach there PROPAGATES (caller fail-closes the whole response). Pass 2 (MET rules) is release-probe-only, discards the rebuilt object (_, count = ...), and catches SelectorBudgetError to break â€” it can only stop further unlock-auditing, never release or block. Verified released-only responses never 403 even with the budget forced to 3 (test_released_rules_never_block_on_budget).
- Gateway non-stream tail (chat_completions.py:485-534): run_data_lock(body_str, ...) returns the withheld body (mask), raises HookBlockedError->403, raises HookFailSafeError->500, or returns content unchanged (pass/not-armed/not-installed). On block/error the exception propagates to the except GatewayError handler and body_str is NEVER returned. Confirmed no path returns the un-withheld body.
- Streaming: armed tenant stream=true is fail-closed BLOCKED before the 200 commits via run_data_lock_stream_preflight (chat_completions.py:362-368, registry.py:303-332); a load error in preflight is likewise blocked. Streamed-withhold is honestly not attempted (bytes already on the wire).

## Attack 2 â€” Caller-forgeable unlock. RESULT: not reachable.

conditions.evaluate (src/data_lock/conditions.py:126-152) reads ONLY the server-resolved identity passed in (team_id/project_id/agent_id from detector._principal -> ctx.tenant_context, detector.py:236-243) and datetime.now(timezone.utc) for TIME. The model JSON output (parsed) is used ONLY as the target of apply_withhold, never as input to evaluate â€” a compromised/malicious upstream model cannot craft output that unlocks a field. A forged project_id/role embedded in the response body is ignored (test_caller_cannot_forge_permission_via_body). PERMISSION rejects empty allow values (conditions.py:103-104), so a missing caller ID ("") can never match an allow entry. TIME is server-clock-only â€” a caller-supplied time field is never read. R2 holds.

## Attack 3 â€” Partial-leak / determinism. RESULT: deterministic, no half-withheld body.

Multi-field: Pass 1 withholds every unmet matching field; a mid-apply SelectorBudgetError (or any unexpected raise) blocks the WHOLE response (the locally-rebuilt current is discarded by the exception). The detector returns either mask with EVERY unmet field withheld, or block â€” never a body with some-but-not-all locked fields released (test_multifield_all_withheld). Immutable rebuild (selector._withhold_one returns a new structure; the original is never mutated) means released fields stay released and there is no aliasing leak.

## Attack 4 â€” CRIT-2 recurrence. RESULT: closed and proven.

"data_lock" is in _VALID_POLICY_TYPES (policy_repository.py:33-35) AND both DB CHECK constraints (policy.py:92-95 ck_policies_policy_type, :156-160 ck_pv_policy_type) AND the reversible migration 0022 (DROP+ADD both constraints, exact-prior-string downgrade). The persist test is genuinely non-stubbed (real upsert_policy -> committed rows -> real RLS load); the auditor ran it and it passes. Vector 6 confirms an unknown policy_type is STILL rejected at the DB layer (constraint live, widening did not loosen). 4-site event discipline is consistent: VALID_EVENT_TYPES (events_audit_log.py:97-100), ACTION_TAKEN_BY_EVENT_TYPE (:183-186), ck_eal_event_type model CHECK (:333), migration 0023, and contracts/events.schema.json.

## Attack 5 â€” Tenant scoping / DoS caps / streaming bypass / audit honesty. RESULT: sound.

- RLS/tenant scoping: config load runs under get_tenant_session(tenant_id) (RLS GUC) + explicit WHERE tenant_id predicate in get_active_policies_for_scope (policy_repository.py:215-221). Events stamped with the server-resolved tenant/team/project via HookContext._stamp_event (context.py:109-118). e2e confirms the audit row lands under the real tenant.
- JSON-traversal DoS caps: MAX_RULES=100, MAX_PATH_DEPTH=16, MAX_PATH_SEGMENTS=16, MAX_TRAVERSAL_NODES=100_000 (shared across all rules in a response), MAX_CONTENT_BYTES=256 KiB, _MAX_ALLOW_VALUES_PER_ATTR=256. Over-cap -> fail-closed (rule rejected at parse -> block; traversal breach -> block).
- Streaming bypass: armed -> pre-flight block before first byte; not-armed -> pass; load error -> block (test_stream_preflight_*).
- Audit honesty: event payloads carry metadata ONLY â€” pattern_name=rule.raw_path (a LOCATION), violation_type in {time, permission, config_error, traversal_budget, envelope_unparseable, content_too_large, streaming_blocked_by_policy}, action_taken. NEVER a field value. AuditLogRepository.append writes via an explicit per-column whitelist (audit_log_repository.py:250-304) with NO **row_data splat, so an event dict cannot inject content into a column. No hash-chain double-emit: run_data_lock raises HookBlockedError(event=None) on block (registry.py:296) and the detector already emitted inside inspect. The events schema is additionalProperties:false with a charset-restricted violation_type (log-injection defense).
- F-005 HIGH-B preserved: in the converged non-stream tail, secret redaction runs on the parsed dict, then json.dumps, then run_data_lock, and the deferred secret_leaked event is emitted ONLY after the FINAL body is confirmed valid JSON (chat_completions.py:462-504). Data-lock composes after secret redaction on the same final body.

---

## Findings (all Low/Med; all fail-CLOSED â€” none leak a locked field)

### MED-1 â€” Contract/runtime divergence: permission allow-list cap (512 vs 256)
- File: contracts/policy.schema.json:364,371,378 (maxItems: 512) vs src/data_lock/conditions.py:34 (_MAX_ALLOW_VALUES_PER_ATTR = 256).
- Severity: Med (availability/correctness; NOT a leak).
- Exploit path: A tenant authors a data_lock permission rule with 257-512 allow values per attribute. It passes signed intake (validate_policy_record against policy.schema.json). At request time _parse_permission_allow raises ConditionError -> DataLockRuleError -> DataLockConfigError -> tier-2 fail-closed: EVERY non-streamed response for that tenant is BLOCKED (403) and every streamed request is blocked, with only a coarse data_lock_error/config_error audit. The policy saved successfully but silently bricks the tenant traffic â€” a self-inflicted DoS that is hard to diagnose. Empirically reproduced (300-value allow-list -> rejected at parse).
- Fix: Make the two bounds equal. Either raise _MAX_ALLOW_VALUES_PER_ATTR to 512 to match the (frozen) contract, or tighten the contract maxItems to 256. Prefer aligning the runtime to the contract value (512) so a contract-valid policy always loads.

### MED-2 â€” Contract/runtime divergence: field_path bounds (256 free-form vs 16-seg/16-depth/restricted-charset)
- File: contracts/policy.schema.json:326-330 (field_path: minLength 1, maxLength 256, any string) vs src/data_lock/selector.py:29-30,38,57-72 (MAX_PATH_SEGMENTS=16, MAX_PATH_DEPTH=16, _KEY_CHARS = [A-Za-z0-9_-]).
- Severity: Med (availability/correctness; NOT a leak).
- Exploit path: A contract-valid field_path such as a 17+ segment dotted path, a 200-char single segment, or a key containing any character outside [A-Za-z0-9_-] (space, unicode, $, :) passes signed intake but raises SelectorError at load -> whole ruleset fail-closed -> the tenant non-streamed responses all 403. Empirically reproduced (17-segment path and "result.full name" both rejected at parse). Same self-inflicted fail-closed DoS as MED-1, and surprising because the contract advertises a far larger field_path surface than the engine accepts.
- Fix: Encode the real selector grammar in the contract: bound maxLength to what 16 segments allows and add a pattern for the bounded dotted-path dialect. Alternatively surface a precise intake-time rejection so the tenant learns at write time, not at request time.

### LOW-1 â€” policy.schema.json was LOCKED at F-008 but amended in place by F-017
- File: contracts/policy.schema.json:2 ($comment: frozen... Any change requires a new $id sentinel:policy:v2) vs the in-place addition of DataLockPolicy and the oneOf entry (:13).
- Severity: Low (governance/process; the addition itself is purely additive and loosens nothing on existing variants â€” the four prior variants are byte-for-byte unchanged).
- Exploit path: None directly. The risk is procedural: a frozen-contract-with-in-place-edits pattern erodes the parser-differential guarantee the lock exists to protect (Sentinel/Orchestrator/Delta must validate identically). If a downstream consumer pins the old $id/hash, a data_lock record validates in Sentinel but is rejected downstream.
- Fix: Confirm api-architect intentionally amended sentinel:policy:v1 (ADR-0020 records this) and update the $comment lock note to reflect the F-017 amendment + new locked commit hash, OR bump to sentinel:policy:v2 with a migration note for Delta/Orchestrator. Per CLAUDE.md the contract wins; this is about keeping the lock annotation truthful.

### LOW-2 â€” _make_post_context returns None on construction failure -> data-lock silently skipped (pre-existing, shared with F-005/F-016)
- File: src/gateway/routes/chat_completions.py:904-905 (except Exception: return None) and the data-lock guard at :490 (post_hook_context is not None).
- Severity: Low (defense-in-depth; not reachable in production â€” HookContext(...) does not raise for a well-formed pre-context, and in this degenerate path the secret + code-scan hooks are equally neutered, so it is not a data-lock regression).
- Exploit path: Theoretical only: if HookContext construction ever raised for an armed data-lock tenant, post_hook_context would be None, data-lock (and secret/code-scan) would be skipped, and the un-withheld body could be returned with a 200. No production trigger was found.
- Fix: Consider making post-context construction failure fail-closed (raise GatewayError internal_error) rather than returning None, so an inspection-context failure blocks rather than silently bypasses ALL post-response detectors. This hardens F-005/F-016/F-017 together.

---

## Honest-language note
No "secure" / "unbreakable" claim is made. This pass found no High/Critical findings. The fail-closed posture is structurally sound across the paths examined; residual risk concentrates in the contract/runtime bound divergences (MED-1, MED-2), which reduce availability for misconfigured tenants but do not release a locked field.
