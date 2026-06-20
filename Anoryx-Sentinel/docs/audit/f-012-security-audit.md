# F-012 Admin Console API — Security Audit (ADR-0014)

- **Status:** PASS (after remediation) — 0 Critical, 0 High open. 1 High + 1 Medium found and FIXED; 1 Medium + 2 Low accepted as documented residuals.
- **Date:** 2026-06-20
- **Auditor:** security-auditor (independent red-team, Opus) + remediation by the F-012 builder.
- **Scope:** the first cross-tenant principal in Sentinel — `src/admin/**`, the `/admin` exempt-prefix wiring in `gateway/middleware/{auth,tenant_context}.py`, `gateway/main.py`, `gateway/routes/audit.py`, the F-012 repository additions, migration 0013, contracts (`openapi.yaml`, `events.schema.json`, `ids.md`), and `tests/admin/**`.

A cross-tenant escalation on this surface is product-ending; the audit was run with that bar.

## Methodology
Adversarial review against ADR-0014's hard rules (R1–R9) and the 14-vector threat model: attempted tenant→admin privilege escalation, admin-token forgery / fail-open, cross-tenant data access via the admin surface, key-secret leakage, RLS-bypass correctness, audit-attribution honesty, the R1⇄R5 reconciliation, input-cap/SSRF/injection, and no-hard-delete/chain-integrity. Plus `semgrep --config p/python,p/security-audit,p/secrets`.

## 14-vector results (all HOLD)
| # | Vector | Result |
|---|---|---|
| 1 | tenant principal reaches admin endpoint | HOLD — `/admin/*` skipped by tenant auth/context, governed solely by `require_admin`; tenant key → 401 |
| 2 | admin forged from tenant creds | HOLD — `require_admin` validates only `SENTINEL_ADMIN_TOKEN`, constant-time, no key-path fall-through |
| 3 | admin cross-tenant op not audited | HOLD — every mutating/cross-tenant-read op emits an `admin_*` event |
| 4 | no admin creds → fail-open | HOLD — token unset/empty → 401 before any session; never tenant data |
| 5 | dishonest attribution | HOLD — `agent_id="admin-console"` + TARGET `tenant_id`; never nil-UUID, never the tenant's own id |
| 6 | key secret re-readable | HOLD — secret returned once; list/get are metadata-only; HMAC-only storage |
| 7 | revoked key accepted | HOLD — gateway `is_active=False` lookup filter denies it |
| 8 | key authenticates as another tenant | HOLD — key→tenant binding + RLS; **plus the HIGH fix below** closes the mint-binding gap |
| 9 | audit read mutates the log | HOLD — serving SELECT zero-write; access event is a separate privileged append (D8) |
| 10 | tenant reads another tenant's events | HOLD — RLS-scoped read; admin reads a named target (audited) |
| 11 | chain status faked | HOLD — `validate_chain()` surfaced honestly |
| 12 | hard delete / chain break | HOLD — soft `is_active` flip; chain re-validates |
| 13 | deactivated tenant's keys work | HOLD — deactivate cascades to keys; gateway denies them |
| 14 | cross-tenant key listing by a tenant | HOLD — admin-only, explicit-target, audited; tenant key → 401 |

Auth boundary, RLS scoping, fail-closed token handling, secret-once handling, and read-only / no-hard-delete invariants are all sound. No High/Critical in the auth/RLS/audit-read core.

## Findings

### HIGH (FIXED) — mint/rotate cross-tenant team/project binding
`POST /admin/tenants/{A}/keys` accepted caller-supplied `team_id`/`project_id` with no check they belong to tenant A. RLS `WITH CHECK` on `virtual_api_keys` constrains only `tenant_id`; Postgres FK referential checks bypass RLS, so a key for tenant A could be bound to tenant B's team/project — cross-tenant attribution corruption (the `admin_key_minted` event would record B's team/project as the key's "real" scope).
- **Fix:** `src/admin/keys.py::_assert_scope_in_tenant` — on the RLS-scoped tenant session, verify `team_id` and `project_id` (and `project.team_id == team_id`) belong to the target tenant; 422 on mismatch. Called before `create()` in `mint_key`. Rotate is unaffected (it copies the existing row's already-scoped team/project).
- **Test:** `tests/admin/test_admin_key_threat_model.py::test_mint_rejects_cross_tenant_scope` (mint for A with B's team/project → 422).

### MEDIUM (FIXED) — unvalidated `{tenant_id}` path param
A non-UUID `{tenant_id}` (≤64 chars) would still cause `emit_admin_event` to append an `admin_audit_accessed` row with a non-UUID `tenant_id`, violating `events.schema.json` (the immutable integration contract consumed by Delta/the Orchestrator) inside the hash chain.
- **Fix:** `src/admin/util.py::validate_tenant_id_path` — a router-level FastAPI dependency on `keys_router`, `audit_log_router`, `control_router` and on the tenant get/deactivate routes; rejects a non-UUID `{tenant_id}` with 422 before any session opens or any event is appended.
- **Test:** `test_admin_route_rejects_non_uuid_tenant` (non-UUID `{tenant_id}` → 422).

### MEDIUM (ACCEPTED RESIDUAL) — non-atomic mutate-then-audit on key/config paths
Key mint/rotate/revoke and config update commit the data mutation on the tenant (RLS) session, then append the audit event on a separate privileged session. The two genuinely cannot share one transaction: `append()` requires the privileged role (global chain tip), the key write requires the tenant RLS session. If the audit append fails after the mutation commits, the action is un-audited and the request returns 500 (the failure is visible, not silent-success).
- **Disposition:** accepted for v1, consistent with the F-011 precedent (compliance meta-events are likewise appended after the read on a separate privileged session). Documented here as a known residual. A future hardening (outbox, or a privileged-session write that sets the tenant GUC to perform both the key write and the append atomically) is the upgrade path. Not a cross-tenant or fail-open risk.

### LOW (ACCEPTED) — `/admin` path base vs `/v1` server
The OpenAPI `servers` base ends in `/v1`, but the admin router serves `/admin/*` (no `/v1`), matching ADR-0014's exempt-prefix wiring and the existing `/metrics` convention. Runtime auth/routing are correct; this is a generated-client base-path note. Disposition: a dedicated admin `servers` entry is a future api-architect change.

### LOW (ACCEPTED, ADR §13.3 deferral) — single shared admin token, no in-app rate-limit
Fork (a): one `SENTINEL_ADMIN_TOKEN`, no per-operator attribution, no revoke-without-redeploy, no in-app lockout on repeated `require_admin` failures (constant-time compare prevents timing leakage; brute force is bounded only by network controls). Accepted per ADR-0014 §13.3; (b)/(c) are the documented upgrade path. Recommend a high-entropy deploy token and adding F-009-style lockout in a follow-up.

## Semgrep
`semgrep --config p/python --config p/security-audit --config p/secrets --severity ERROR` over the F-012 surface: 0 secrets findings; 1 pre-existing `avoid-sqlalchemy-text` on `audit_log_repository.py` `pg_advisory_xact_lock(<int constant>)` (no user input — false positive on unchanged F-003 code, not F-012).

## Verdict
**PASS.** The one High and one Medium that constituted contract/security defects are fixed with regression tests; the remaining Medium and two Lows are accepted, documented residuals with no cross-tenant or fail-open exposure. The admin-auth boundary, RLS scoping, honest attribution, read-only audit serving path, secret-once handling, and no-hard-delete invariants hold.
