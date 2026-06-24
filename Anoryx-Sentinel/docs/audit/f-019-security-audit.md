# F-019 Model-Approval — Independent Red-Team Security Audit

- Feature: F-019 — default-deny model governance (ADR-0022) on the F-008 evaluate_model_policies seam
- Branch: task/F-019-model-approval-native
- Auditor posture: Independent. Did NOT write this code. No benefit of the doubt. Read the real code paths; tests corroborate but were not trusted.
- Date: 2026-06-24
- Semgrep: p/python + p/security-audit + p/secrets, severity ERROR, 12 changed source files yields 0 findings, 0 scan errors (semgrep 1.166.0).
- DB-gated tests: Not executed here (no DATABASE_URL / APP_DATABASE_URL); they skip by design. Audit is based on reading the real code paths, not test execution.

## Verdict: PASS

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 0 |
| Medium   | 0 |
| Low      | 2 |

No High or Critical findings in this pass. The two Low items are non-exploitable (documentation / observability nuances), recorded for completeness.

---

## Threat-by-threat result (7 primary threats + the F-008 repair)

### 1. SELF-APPROVAL (data-plane to approve/deny) — CLOSED
A /v1 virtual-API-key caller cannot reach the approval surface by any header/body/claim.
- model_approval_router is mounted under admin_router (src/admin/router.py:23-27,50) whose router-level dependency is Depends(require_admin) and whose prefix is /admin.
- /admin/* is skipped by AuthMiddleware/TenantContextMiddleware; the only credentials require_admin (src/admin/auth.py:105-148) accepts are the constant-time-compared break-glass env token and an HMAC SSO operator-session. It NEVER consults the virtual-key path, so a tenant key on /admin yields 401 with no fall-through.
- The router additionally pins validate_tenant_id_path + enforce_admin_scope (src/admin/model_approval.py:46-49). Three independent layers. A /v1 body field cannot route to an /admin path. Confirmed structurally; corroborated by test_data_plane_cannot_approve_model (401, inventory stays empty).

### 2. APPROVAL FORGERY / ATTRIBUTION — CLOSED
The operator identity stamped on a transition is taken from the authenticated principal, never caller-supplied.
- actor_id(request) (src/admin/util.py:46-60) reads request.state.admin_auth admin_user_id, set ONLY by require_admin from the verified SSO session (auth.py:93-102) or None for break-glass. No body/query/header path into it.
- _decide passes aid = actor_id(request) into both repo.transition(operator_id=aid) and emit_admin_event(actor_id=aid) (model_approval.py:144-179). The audit row agent_id is the reserved admin-console slug (audit.py:99); tenant_id is the TARGET tenant, never nil-UUID, never the tenant own identity.
- emit_admin_event whitelists event_type against ADMIN_EVENT_TYPES (audit.py:88-89). Corroborated by test_approval_attributed_to_operator.

### 3. ENFORCEMENT BYPASS / FAIL-OPEN — CLOSED (fail-CLOSED confirmed)
evaluate_model_policies (src/policy/enforcement.py:236-298):
- F-008 resolution runs first; an explicit model_denylist deny / not-in-allowlist short-circuits and stays absolute (:268-272).
- The F-019 gate activates only when a model_approval policy matches the scope (_select_approval_policy, :218-233). If none matches, the F-008 result stands unchanged (:285-287), so tenants who do not opt in are unaffected.
- When active: state not equal to approved (pending/denied/unknown) yields ModelDeny reason model_not_approved (:295-297). Any get_state exception yields ModelDeny (:289-294, fail-closed, R3).
- Unknown model yields the UNKNOWN_STATE sentinel (model_inventory_repository.py:82-90) then DENY. Exact string match on model_id, so casing/whitespace variants map to unknown then DENY (fail-closed; no normalization bypass).
- A malformed stored model_approval payload raises at the Pydantic parse (enforcement.py:281), propagating to the broad except Exception in route_non_stream/route_stream and yielding internal_error (BLOCK). No path returns ModelAllow for a non-approved model.
- model_approval deliberately has NO effective_until and does NOT reuse allowlist_active (:276-278, variants/model_approval.py:42-46), so a malformed expiry cannot silently disable the gate (the fail-open trap was explicitly avoided).
- Deny reaches the wire via the existing _policy_deny then GatewayError(policy_blocked) 403, pre-upstream (selection.py:205-214,333-343,518-528), on non-stream + stream. Corroborated by the non-stubbed e2e (test_unapproved_model_blocked_e2e 403; test_approved_model_allowed_e2e 200).

### 4. CROSS-TENANT — CLOSED
- SSO operator is tenant-pinned: enforce_admin_scope 403s unless admin_auth.tenant_id equals path tenant_id (src/admin/scope.py:81-90). An operator for tenant A cannot approve/list for tenant B. Corroborated by test_cross_tenant_approval_denied.
- model_inventory RLS: migration 0026 ENABLE + FORCE ROW LEVEL SECURITY with the verbatim strict NULLIF tenant_isolation predicate (USING + WITH CHECK) and GRANT SELECT, INSERT, UPDATE (no DELETE) to sentinel_app (0026_model_inventory.py:38-51). The repository adds an explicit tenant_id predicate as the second lock. Runtime reads use get_tenant_session (sentinel_app, NOBYPASSRLS). Corroborated by test_inventory_tenant_scoped (tenant B sees nothing even when passing A id).
- Break-glass is intentionally cross-tenant (recovery, R5) and is audited on every action, within the documented trust model.

### 5. POLICY PERSISTENCE (CRIT-2) — CLOSED (not inert)
model_approval is accepted at every gate:
- _VALID_POLICY_TYPES (policy_repository.py:33-42).
- BOTH CHECK constraints: ck_policies_policy_type and ck_pv_policy_type (models/policy.py:92-98,158-163) and migration 0025 (DROP+ADD both, reversible).
- oneOf dispatch + closed (additionalProperties false) payload with enforcement_mode const default_deny in contracts/policy.schema.json:11,172-203.
- Typed view registered in _VIEW_BY_TYPE (policy/variants/__init__.py:23,37).
The non-stubbed persist-then-load path is exercised by test_crit2_policy_persist and the e2e seed (real PolicyRepository.upsert_policy).

### 6. HASH-CHAIN — INTACT
- The F-019 events reuse the existing model column and the opt-in actor_id rule; no new hashed column, no change to CANONICAL_FIELDS or canonical_json (hash_chain.py). model is already in CANONICAL_FIELDS (line 73) and is therefore bound into the row hash (tamper-evident).
- emit_admin_event appends via AuditLogRepository.append, which hard-asserts a privileged session via the load-bearing SELECT current_user role check (audit_log_repository.py:173-218) before touching the global chain. The tenant state write and audit append are on separate sessions by necessity (the chain needs the global privileged view); the documented audit-before-state ordering guarantees no committed state change without a committed audit row (model_approval.py:17-23,160-181).

### 7. STATE MACHINE — SOUND
_VALID_TRANSITIONS (model_inventory_repository.py:32-37): pending to approved or denied, approved to denied, denied to approved. No edge returns to pending. Same-state and absent-model requests raise (:147-156), surfaced as 409 by _decide. adopt is idempotent and never resets a decided model to pending (:92-120; no TOCTOU, gated on the insert created flag). A denied-to-approved transition mutates state AND appends a fresh audited event; prior audit rows are never erased (append-only). Corroborated by test_state_machine_valid_and_invalid_edges.

### F-008 double-begin repair (src/gateway/router/selection.py) — SAFE
_enforce_policies_pre_request (:179-202) and _resolve_policy (:217-231) no longer wrap their reads in a redundant async-with session.begin(). get_tenant_session autobegins via its set_config execute; both blocks are read-only, so the reads run in the autobegun transaction (the established admin/control.py / bulk/worker.py pattern). The GUC is transaction-local (is_local true); a single read transaction per session preserves correct RLS scoping. No isolation weakening, and this fix makes the previously-inert F-008 + F-019 enforcement actually execute (an inert-enforcement bug of the F-016 class, now closed and proven by the non-stubbed e2e).

---

## Low findings (non-exploitable; recorded)

### LOW-1 — ADR section 5.4 wording vs code: model_id IS hashed, not unhashed
- File: docs/adr/0022-model-approval-policies.md:136-138 vs src/persistence/hash_chain.py:73.
- Issue: ADR section 5.4 says model_id/state ride in event_data (unhashed). In reality the model column is in CANONICAL_FIELDS, so the operator events model_id IS bound into the row hash. The code is MORE tamper-evident than documented.
- Exploit path: None. The stricter (hashing) behavior is the safe one; documentation inaccuracy only.
- Fix: Correct ADR section 5.4 to state model_id rides the hashed model column.

### LOW-2 — Malformed approval-policy payload yields generic 500, not 403, masking root cause
- File: src/policy/enforcement.py:279-283 (parse outside the try) then src/gateway/router/selection.py:330-332,514-517 (broad except Exception).
- Issue: A model_approval row whose policy_payload fails Pydantic validation raises before the get_state try/except, surfacing as a generic internal_error (500) rather than the cleaner policy_blocked (403). Behavior is still fail-CLOSED (request blocked), but the root cause is obscured in logs.
- Exploit path: None (blocked outcome). Reaching it requires a malformed row already stored, which the intake closed-schema + signature verification prevents.
- Fix (optional): Wrap the approval-view parse in the same fail-closed try/except so a corrupt switch row yields a deterministic 403 with reason model_not_approved and a precise log line.

---

## Notes / scope honesty
- F-019 governs models routed through Sentinel /v1 surface; a caller bypassing the gateway entirely is out of scope (gateway perimeter, not this feature), consistent with ADR section 4.
- Break-glass is cross-tenant by design (recovery), audited on every action.
- The approval workflow is single-operator / single-transition in v1 (no multi-party governance), stated honestly in ADR sections 4 and 8.
