# ADR-0017 — RBAC-Gated Dashboards: Locally-Issued Role-Tagged Access Tokens

- **Status:** Accepted
- **Date:** 2026-07-09
- **Task:** D-017 (Strict RBAC operational dashboards) · Builder: orchestration-hooks ·
  Phase 3 (post-investment vision) — the fifth task built past Delta's committed MVP
  (D-001→D-012), continuing directly after D-016 per the user's explicit instruction
  to keep going into the vision tier.
- **Depends on:** D-013 (indirectly — no code dependency; the roadmap names it
  alongside F-014, but D-017's actual scope, "operational dashboards," is D-008's
  surface, not D-013's), F-014 (Anoryx-Sentinel's already-shipped SSO/OIDC/SAML +
  RBAC feature, ADR-0017 in Sentinel's own `docs/adr/` — **read for its role
  vocabulary, not integrated with**; see Fork 1 and §3).
- **Builds on:** `delta.allocation_admin.config`'s own docstring, written at D-007's
  original construction: *"No SSO/operator-session tier is built here (Sentinel's
  ADR-0017 tier) — a lean, single break-glass credential is the right STEP-0 fork for
  a first admin surface with no existing operator-identity system in Delta to
  federate with (banked rule #13)."* This task is the STEP-1 this comment always
  pointed at — the first time Delta itself builds any notion of a role/tier, six
  tasks after D-007 first deferred it.
- **Supersedes:** nothing. Adds a new `delta.rbac` package, one new table
  (`access_tokens`) via migration 0011, one new router mount to
  `allocation_admin/app.py`, and modifies exactly ONE existing file's runtime
  behavior: `dashboards/router.py`'s router-level auth dependency (additive — see
  Fork 3). No other D-007–D-016 file is touched.

## 1. Context

The roadmap's literal text for D-017 is: *"Org-tier-scoped dashboards — users
view/execute only what their tier authorizes."* Tagged `🏦 POST-INVESTMENT`, sized
"16-22h · Risk: Medium," depending on D-013 and F-014. Taken at face value this could
mean either (a) real SSO/per-person identity federated with Sentinel's already-shipped
F-014 (Anoryx-Sentinel's own `docs/adr/0017-sso-oidc-saml.md` — OIDC + SAML, IdP
config, per-tenant group→role mapping, signed operator-sessions), or (b) retrofitting
role-based access control across every one of Delta's seven existing admin surfaces
(D-007/D-008/D-011/D-012/D-013/D-014/D-015/D-016). Both are large, cross-cutting
changes this run cannot honestly deliver unattended: (a) is real cross-product
identity federation between two separate admin consoles with separate break-glass
tokens and no existing trust relationship — a project of its own, not a bolt-on; (b)
is a blast-radius-of-seven-packages migration that deserves its own dedicated review
pass, not a side effect of "add RBAC." This ADR applies the discipline every prior
D-013→D-016 ADR already established: a bounded, honestly-scoped vertical slice — a
LOCAL, Delta-native two-role model (mirroring Sentinel's own role NAMING for
ecosystem consistency, not its identity architecture) gating the one existing surface
the roadmap's own wording most literally names: D-008's dashboards.

## 2. Decision summary (forks)

| Fork | Decision | Rationale |
|---|---|---|
| **1 — two seeded roles, `tenant_admin`/`tenant_auditor`, mirroring Sentinel's own F-014/ADR-0017 vocabulary — but a LOCAL, token-based identity model, not real SSO** | `access_tokens.role` is a plain string CHECK-constrained to `('tenant_admin', 'tenant_auditor')` — the exact two role names Sentinel's ADR-0017 §2 seeds (`admin_roles`: "`tenant_admin` (manage own tenant)... and `tenant_auditor` (read-only)"). Delta's own tokens are locally issued and hashed (SHA-256), NOT OIDC/SAML-backed operator-sessions tied to a real per-person `idp_subject`. | Reusing Sentinel's exact role names (rather than inventing Delta-local ones like "viewer"/"operator") is a genuine, low-cost ecosystem-consistency win — an operator who already knows Sentinel's RBAC vocabulary immediately understands Delta's. Building real OIDC/SAML federation with Sentinel's IdP-config/group-mapping machinery is a materially larger, cross-repository integration this task does not attempt — named explicitly in §3. |
| **2 — the break-glass `DELTA_ADMIN_TOKEN` continues to work completely unchanged, treated as implicit `tenant_admin` for any tenant** | `rbac.auth.authorize` checks the presented bearer against the break-glass token FIRST (the exact `hmac.compare_digest` check `allocation_admin.auth.require_admin` already uses) and short-circuits to `"tenant_admin"` before ever touching the database. Only a non-matching bearer falls through to the issued-token hash lookup. | Zero blast radius on every existing D-007–D-016 caller, test, and operator workflow — the single most important backward-compatibility guarantee in this task, verified directly by `test_dashboards_still_works_with_break_glass_token`. This is also how a tenant bootstraps its FIRST issued token: the break-glass bearer must be able to call `POST /rbac/tokens` before any tenant-scoped token exists. |
| **3 — ONLY `dashboards/router.py` is retrofitted; the other six D-007–D-016 routers are untouched** | `dashboards/router.py`'s router-level `dependencies=[Depends(require_admin)]` becomes `dependencies=[Depends(require_role("tenant_auditor"))]` — a strict superset (Fork 2) — and that is the ONLY line changed in any pre-existing package's runtime file across this entire task. `allocation_admin`, `forecasting`, `chargeback`, `crm`, `erp`, `pm`, `capacity` all keep `require_admin`-only auth. | D-008's dashboards is the most literal reading of the roadmap's own "operational dashboards" wording — genuinely gating it (not a decorative parallel endpoint) is the honest, concrete deliverable. Retrofitting the other six surfaces is a real, larger migration that deserves its own dedicated review (each has its own write-path race/idempotency/audit-chain considerations D-017 has not re-examined) — named explicitly as deferred in §3, not silently skipped. |
| **4 — token issuance/revocation is itself gated at `tenant_admin`, checked directly (not via the router-level query-param dependency)** | `rbac/router.py`'s three routes call `rbac.auth.authorize(request, req.tenant_id, "tenant_admin")` directly, reading `tenant_id` from the parsed request BODY — not the router-level `Depends(require_role(...))` shape used for dashboards, whose dependency needs `tenant_id` as a QUERY parameter to compose with three GET routes. | Managing WHO has access is itself the most sensitive action this package exposes — only `tenant_admin` (or the break-glass bearer) may create or revoke a token, mirroring "least privilege to manage privilege." The direct-call shape (vs. the query-param dependency) is a deliberate, documented API design choice (`auth.py`'s own docstring) driven by FastAPI's dependency-resolution mechanics for POST-body-vs-query-param parameters, not an inconsistency. |
| **5 — only `token_hash` (SHA-256) is ever stored; the raw token is a one-time reveal** | `AccessTokenIssuedView` (returned ONLY by `POST /tokens`) is the sole response shape ever carrying the raw value; `AccessTokenView` (every other response) never does. A lost token cannot be recovered — it must be revoked and a new one issued. | Standard API-key/secret-issuance hygiene (mirrors how any credential — a password, an SSH key, a cloud API key — is handled): a database compromise never leaks a usable bearer credential, only its hash. |
| **6 — a presented token is looked up within the tenant-scoped RLS session for the caller-supplied `tenant_id`, not a separate cross-tenant lookup + mismatch check** | `rbac.auth.authorize(request, tenant_id, minimum)` opens `get_tenant_session(tenant_id)` (the SAME RLS-scoped session every other Delta package uses) and calls `get_active_token_by_hash` inside it. A token issued for a DIFFERENT tenant is simply invisible in that session — the lookup returns `None`, which resolves to a generic 401, not a distinguishable "wrong tenant" signal. | The database's own RLS predicate IS the cross-tenant check — adding a second, separate application-layer mismatch check would be redundant complexity protecting an invariant RLS already guarantees. This mirrors D-013/D-014's own "no extra scope check where the FK/RLS already proves it" reasoning. |
| **7 — mounted on the existing admin app, not a new process** | `POST/GET /v1/admin/rbac/tokens`, `POST /v1/admin/rbac/tokens/{id}/revoke` on the same D-007 admin app. | Same operators, same auth boundary, same trust boundary — mirrors D-008/.../D-016's own reasoning for not standing up a second process. |

## 3. Honest deferrals (named, not half-built)

- **No real SSO/OIDC/SAML, no per-person operator identity.** A token represents a
  ROLE, not a specific human — there is no `idp_subject`, no `display_name`, no
  `last_login_at`, no audit trail attributing an action to a named person (only to
  the token's `name` label, an operator-chosen string, not a verified identity).
  Real per-operator accountability requires federating with Anoryx-Sentinel's own
  already-shipped F-014/ADR-0017 identity layer (`admin_users`/`admin_roles`/
  `admin_role_assignments`, OIDC/SAML assertion validation, signed operator-
  sessions) — named here as the concrete, already-built future integration target,
  not a vague "some future SSO."
- **Only D-008's dashboards router is gated.** The other six admin surfaces
  (allocations, forecasting, chargeback, CRM, ERP, PM, capacity) remain
  `require_admin`-only — a real, large, cross-cutting retrofit explicitly deferred
  (Fork 3), not silently incomplete.
- **No fine-grained permissions.** Two seeded roles, not a permissions matrix per
  endpoint/action — mirrors Sentinel's own ADR-0017 §13.3 explicit "minimal RBAC...
  not fine-grained permissions" scope statement for its v1.
- **No token expiry/rotation policy, no rate limiting on the auth check itself.** A
  token is valid until explicitly revoked (no TTL); repeated failed-auth attempts are
  not throttled beyond whatever sits in front of the admin API already (mirrors
  D-007's own break-glass token's existing residual risk, noted honestly there too).
- **No in-app audit trail for token issuance/revocation.** Unlike D-014's purchase-
  order decisions, token issuance/revocation is NOT wired into D-009's hash-chained
  audit log — mirrors D-013/D-015's reasoning (an access-control action, not a
  financial transaction; D-009's own stated scope is Delta's automated FINANCIAL
  workflows).
- **No self-service token rotation UI beyond issue/revoke.** An operator who loses a
  token revokes it and issues a new one — there is no "rotate" action that revokes
  and reissues atomically.

## 4. Threat model / correctness cross-reference

| Vector | Mitigation | Verified by |
|---|---|---|
| Cross-tenant token/dashboard-data leak | Every lookup runs on the caller-supplied `tenant_id`'s RLS-scoped `AsyncSession`; `access_tokens`' RLS predicate is the same fail-closed `tenant_id = NULLIF(current_setting(...), '')` as every prior Delta migration; a wrong-tenant token is simply invisible (Fork 6) | `test_cross_tenant_isolation_tokens_invisible_to_other_tenant`, `test_cross_tenant_token_cannot_read_other_tenant_dashboards` |
| The break-glass bearer stops working after this task | `authorize()` checks it FIRST via the identical `hmac.compare_digest` comparison `require_admin` already used, before any DB call | `test_dashboards_still_works_with_break_glass_token` |
| A revoked token still grants access | `get_active_token_by_hash` filters `revoked_at IS NULL` at the SQL layer (not just a Python-side check the caller could skip) | `test_get_active_token_by_hash_excludes_revoked_token`, `test_resolve_role_from_bearer_revoked_token_returns_none`, the full HTTP flow test's step 6 |
| A `tenant_auditor` token performs an admin-only action (issuing/revoking tokens) | `role_at_least` is checked against the SAME two-entry rank table on every gated route; `POST /tokens`/`POST /tokens/{id}/revoke` require `tenant_admin` explicitly | `test_auditor_does_not_satisfy_admin_minimum` (pure), `test_full_rbac_flow_over_http` step 3 (an issued auditor token attempting `POST /tokens` gets 401) |
| A raw token is recoverable from the database or an API response after issuance | Only `token_hash` (SHA-256) is ever persisted; `AccessTokenView` (every response except the one-time `POST /tokens` reply) has no `token` field | `test_list_token_views_never_exposes_raw_token`, the HTTP flow test's step 4 (`"token" not in listed[0]`) |
| An unrecognized/malformed role string silently grants access | `role_at_least` returns `False` for any role not in the fixed two-entry rank table — fail-closed by construction, not by an exhaustive-enum assumption | `test_unrecognized_actual_role_fails_closed`, `test_unrecognized_minimum_role_fails_closed`, `test_both_unrecognized_fails_closed` |
| Auth bypass on any of the 3 new `rbac` routes or the retrofitted dashboards routes | Every `rbac` route calls `authorize()` as its first statement (no route skips it); `dashboards`' router-level `Depends(require_role("tenant_auditor"))` covers all 3 GET routes with no per-route opt-out | `test_rbac_tokens_endpoint_401_without_bearer`, `test_dashboards_still_401_without_bearer`, `test_bogus_bearer_token_rejected_by_rbac_endpoints` |
| Control-character / log-injection via a token's `name` field | Same `_reject_control_chars` discipline as every prior Delta package | `test_token_create_rejects_control_chars_in_name` |
| SQL injection via any RBAC identifier or free-text field | Every query is a parameterized SQLAlchemy Core statement — no raw string-interpolated SQL anywhere in `delta.rbac.store` | code review |

## 5. Verification

- `black --check` / `ruff check .` clean on `src/delta/rbac`, the modified
  `src/delta/dashboards/router.py`, `src/delta/allocation_admin/app.py`, and
  `tests/rbac`.
- New `tests/rbac/` suite: 34 tests — 8 pure role-rank unit tests
  (`test_role_rank.py`, no DB/I/O), 6 pure schema-validation tests
  (`test_schemas.py`), 8 DB-backed store tests (`test_store_db.py`), 6 DB-backed
  service tests (`test_service_db.py`, incl. the one-time-reveal and revoked-token
  round-trips), 8 non-stubbed HTTP e2e tests (`test_router_e2e.py`, covering both the
  new `/rbac/*` surface AND the dashboards retrofit — real ASGI app, real auth, real
  DB). `tests/dashboards/`'s own existing e2e suite stays green unmodified,
  confirming Fork 2's backward-compatibility claim end to end, not just by code
  review.
- Full existing Delta suite green (785 passed, 15 skipped) — zero regressions.
- Migration 0011 verified round-trip (`alembic upgrade head` → `downgrade -1` →
  `upgrade head`) against a live local Postgres, `delta_app` role provisioned exactly
  as every prior migration's test harness does.
- Frontend: `npx tsc --noEmit` clean, `eslint` clean (0 warnings/errors on all new/
  modified files), `npm run build` succeeds (`/rbac` registered as a dynamic route),
  and the frontend's own `vitest` suite (45 tests) stays green. Live browser smoke
  test performed against a real running backend with real data entered through the UI
  itself: logged in via the break-glass token, confirmed the (unmodified) dashboards
  page still loads, issued a `tenant_auditor` token via the RBAC page (a real 43-
  character `secrets.token_urlsafe(32)` value, revealed exactly once), confirmed that
  raw token genuinely authenticates a direct `GET /v1/admin/dashboards/summary` call
  (200), confirmed that same token is genuinely REJECTED attempting
  `POST /v1/admin/rbac/tokens` (401 — cannot self-escalate), revoked the token via the
  UI, and confirmed the revoked token's dashboard access is genuinely rejected
  afterward (401) — every step verified against the real backend, not mocked.
- Independent security-auditor review: scheduled next (dispatched after this ADR is
  committed, per the established D-013→D-016 procedure) — this is a genuine new auth
  surface, so it receives the highest scrutiny of any task this session; findings and
  fixes, if any, will be recorded in `docs/audit/d-017-security-audit.md` before this
  branch merges.

## 6. Alternatives considered

- **Real SSO/OIDC/SAML federation with Anoryx-Sentinel's F-014.** Rejected (Fork 1):
  a genuine cross-repository identity-federation project (trusting Sentinel's IdP,
  validating its signed operator-sessions, mapping Sentinel roles to Delta actions)
  that deserves its own dedicated ADR and review cycle, not a bolt-on to a 16-22h
  task — named explicitly as the concrete future integration target in §3, unlike a
  vague "some future SSO" deferral.
- **Retrofitting `require_role` across all seven D-007–D-016 admin surfaces.**
  Rejected (Fork 3): a real, large migration whose blast radius (every write-path's
  own idempotency/race/audit-chain considerations, re-examined per surface) is out of
  scope for one unattended pass — D-008's dashboards is the literal, bounded, honest
  slice the roadmap's own wording names.
- **Inventing Delta-local role names (e.g. "viewer"/"operator"/"admin") instead of
  reusing Sentinel's `tenant_admin`/`tenant_auditor`.** Rejected (Fork 1): mirroring
  the ecosystem's own already-established vocabulary is a real, low-cost consistency
  win with no offsetting downside — this is not full RBAC-model reuse (Fork 1's
  identity architecture is deliberately simpler), only naming consistency.
- **A separate cross-tenant token lookup plus an explicit tenant-mismatch check.**
  Rejected (Fork 6): the tenant-scoped RLS session a presented token is looked up
  within already makes a wrong-tenant token invisible — a second, redundant
  application-layer check would protect an invariant the database already
  guarantees, adding complexity with no corresponding security benefit.
