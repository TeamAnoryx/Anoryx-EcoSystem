# F-021 Advanced Governance UI — Independent Security Audit

- Feature: F-021 (ADR-0024) — model-retirement workflow + operator governance UI
- Branch: task/F-021-governance-ui-native
- Auditor role: independent red-team (did NOT write this code; no benefit of the doubt)
- Date: 2026-06-25
- Verdict: PASS — 0 CRITICAL, 0 HIGH. (2 LOW, informational; no escalation.)
Per house style: not asserting secure. Stating: no High/Critical findings in this pass.

## Scope of change (threat-modeled)

Backend:
- model_inventory.retire_at nullable TIMESTAMPTZ (migration 0031; additive, no state CHECK widen).
- ModelInventoryRepository.set_retirement (requires state==approved) / clear_retirement.
- evaluate_model_policies (src/policy/enforcement.py): get_state -> get_row; DENY approved model when now > retire_at (reason model_retired), fail-closed.
- New operator endpoints POST /admin/tenants/{tid}/models/retire + /unretire (src/admin/model_approval.py).
- 2 new audit event types (model_retirement_scheduled / _cancelled), action-only, no new hash-folded column.

Frontend: model-governance-panel.tsx (client island via BFF clientApi) + governance page mount.

Contracts: openapi.yaml + events.schema.json extended.

New trust boundaries: (a) two new mutating admin routes; (b) a new runtime DENY branch on the /v1 enforcement seam; (c) a new client island calling the BFF. All three were attacked directly.

## Empirical verification (ran against a live Postgres in this env)

Admin auth / threat-model vectors — ALL RAN + PASSED (not skipped):
- test_data_plane_cannot_retire_model PASS — virtual-API-key -> 401 on retire AND unretire (PRIMARY vector).
- test_only_operator_can_retire PASS — break-glass 200; SSO tenant_auditor write -> 403 (role gate).
- test_cross_tenant_retire_denied PASS — operator pinned to A -> 403 on tenant B retire.
- test_retire_at_must_be_future PASS — past/now retire_at -> 400.
- test_retire_requires_approved_model PASS — absent -> 404, non-approved -> 409.
- test_retire_unretire_attributed_to_operator PASS — actor_id==operator, agent_id==admin-console, tenant_id==TARGET, model==model_id; never nil-UUID.

Enforcement (non-inert + fail-closed) — ALL RAN + PASSED:
- test_retired_model_blocked_e2e PASS — REAL gateway /v1 path, ZERO stubs: approved-then-retired (past retire_at) -> 403 policy_blocked. Proves enforcement is not cosmetic.
- test_past_grace_model_denied PASS — past grace -> ModelDeny(reason=model_retired).
- test_in_grace_model_still_allowed PASS — within grace -> ModelAllow.
- test_enforcement_fails_closed PASS — get_row error -> DENY (fail-closed; test patches get_row, the real call site).
- test_no_approval_policy_preserves_f008 PASS — no regression for non-opt-in tenants.

Migration round-trip / head-pin: test_current_head_is_0031, downgrade/reapply, test_migration_reversible (shadow_ai bumped 0030->0031) PASS.

Frontend: panel render lane model-governance-panel.test.tsx — 16 PASS; check:token is a real CI canary scan (exits 2 locally only because no canary build present — not a finding).

Semgrep p/python p/security-audit p/secrets --severity=ERROR over all 7 changed/new Python files: 0 results, 0 scan errors.

Secret/PII/log grep over the full F-021 backend diff + new files: 0 logging statements, 0 secret/credential patterns. retire_at and model NAME are never logged.

## Attack surface findings

### 1. Authority / non-forgeable (PRIMARY) — NO FINDING
retire/unretire are declared on model_approval_router, which carries router-level Depends(validate_tenant_id_path), Depends(enforce_admin_scope) (model_approval.py:47-50). That router is mounted under admin_router whose parent dependency is Depends(require_admin) (router.py:24-27, :51). Auth inherited by construction — verified empirically: a virtual-API-key bearer gets 401. Forging is moot: the principal is read from request.state.admin_auth set by require_admin (constant-time env compare or HMAC operator-session verify); actor_id/tenant_id are never caller-supplied. POST is a write method, so an SSO tenant_auditor is 403 at enforce_admin_scope (scope.py:87). Fail-closed on missing/unknown auth kind (scope.py:54, :93).

### 2. Cross-tenant isolation — NO FINDING
SSO operators are tenant-pinned: enforce_admin_scope requires admin_auth.tenant_id == path tenant_id else 403 (scope.py:83-84). retire/unretire run on get_tenant_session(tenant_id) (RLS) AND the repo uses an explicit tenant_id predicate in get_row (model_inventory_repository.py:75-78) — the F-003b two-lock pattern. retire_at is per-row, per-tenant. Empirically: operator A -> 403 on tenant B. Break-glass is intentionally cross-tenant (R5, recovery), audited.

### 3. Retirement enforcement — REAL, non-inert, fail-closed — NO FINDING
The DENY is produced by real backend code on the /v1 path (proven by the zero-stub e2e returning 403). The fail-closed try/except wraps get_row (enforcement.py:294-299); a load error -> ModelDeny. The now > row.retire_at comparison cannot fail-OPEN: naive now is normalized to aware UTC (enforcement.py:258-259) and the column is TIMESTAMPTZ; even a TypeError is caught by both gateway callers wrapping _enforce_policies_pre_request in except Exception -> internal_error = fail-safe BLOCK (selection.py:330-332, :514-516). retire_at None -> allowed (correct). Strict > means at-deadline is still in grace (benign).

### 4. Token / secret hygiene — NO FINDING
SENTINEL_ADMIN_TOKEN and SESSION_SECRET are read only in frontend/src/lib/env.ts (import server-only), distinct values, no NEXT_PUBLIC_ variant, eslint funnels all process.env through this file. The BFF injects the bearer server-side (bff.ts:99,109) and never echoes it. The client island receives only tenantId. check:token canary scan guards the built bundle in CI. The 2 new audit events carry only model NAME + actor_id (opaque admin_users.id) + TARGET tenant + WILDCARD_UUID team/project — no URL, credential, PII, or even the retire_at deadline.

### 5. BFF-only / no silent endpoint — NO FINDING
The panel calls only clientApi.get/post -> /api/admin/<path> (relative same-origin BFF), never Sentinel directly (client-api.ts:23,48). The BFF catch-all allow-lists segments[0] to {tenants, whoami} (bff.ts:26,92), traversal-guards every segment (rejects dot, dotdot, slash, backslash, bff.ts:95) and encodeURIComponent-s them (bff.ts:100) — no SSRF/path-traversal. CSRF guard on state-changing methods (route.ts:25). retire/unretire backend routes were built in model_approval.py (not smuggled from the frontend).

### 6. UI honesty — NO FINDING
retirementLabel renders Retired-blocked-since-<date> once past grace and Retiring-usable-until-<date> within grace (model-governance-panel.tsx:34-49); the persistent enforcement note states retirement is gateway-enforced fail-closed regardless of UI state. Label matches backend reality. All fields render as inert React text; no dangerouslySetInnerHTML.

### 7. Input / bounds — NO FINDING
ModelRetireRequest is extra=forbid, model_id bounded [1,256], retire_at: datetime (pydantic rejects malformed/out-of-range -> 422). A malformed body 422s before any state change (cannot disable the gate). Past/now retire_at -> 400 future-guard (model_approval.py:310-311). validate_tenant_id_path enforces UUID shape (util.py:22-33) before any session/audit.

### 8. Audit integrity (hash chain) — NO FINDING
Both new event types are action-only. Their content fields (event_type, action_taken=logged, model, actor_id opt-in, tenant_id, team/project WILDCARD_UUID) are ALL already in CANONICAL_FIELDS (hash_chain.py:63-116) or the actor_id opt-in-when-present rule — no new hash-folded column, so historical row hashes are unchanged and the chain does not fork. retire/unretire are audited audit-before-state: set_retirement flush (no commit) -> privileged emit_admin_event (committed) -> ts.commit() (model_approval.py:313-335). emit_admin_event reused unchanged.

### 9. Regression from get_state -> get_row — NO FINDING
get_state now has zero production callers outside the repo. The enforcement uses get_row, a functional superset (state = row.state if row else unknown, enforcement.py:300) — identical default-deny semantics. No allow-path opened.

## Findings table

| Sev | File:line | Issue | Exploit path | Fix |
|-----|-----------|-------|--------------|-----|
| Low | frontend/src/lib/bff.ts:46-85 | Deprecated LegacyProxyInput branch synthesizes a break-glass session from authenticated:true. | Not reachable from the F-021 route (route.ts always passes session); legacy/test callers only. No live exploit. | Remove once no caller uses the legacy shape; keep bff.test.ts vector 3 (unauth -> 401, no fetch). |
| Low | src/admin/model_approval.py:308 | retire_at has no upper bound (year 9999 accepted). | Operator could set an effectively-never deadline; benign UX, not a bypass (model stays approved = F-019 behavior). | Optional: cap to a sane horizon in ModelRetireRequest. Not required. |

## Conclusion

PASS. 0 CRITICAL, 0 HIGH findings in this pass. The two LOW items are informational and do not gate merge or require human escalation. Authority is non-forgeable and inherited by construction; cross-tenant isolation holds under tenant-pin + RLS + explicit-predicate; retirement enforcement is empirically proven non-inert and fail-closed on the real /v1 path with zero stubs; token hygiene, BFF-only access, UI honesty, input bounds, audit-chain integrity, and the get_state->get_row migration are all sound.
