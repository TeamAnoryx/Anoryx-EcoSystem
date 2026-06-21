# F-014 SSO (OIDC + SAML) — Security Audit (ADR-0017)

- **Status:** PASS — 0 Critical, 0 High. 1 Medium found and **FIXED** (audit-integrity: an SSO operator-session could emit a system-scoped `admin_breakglass_used`); 1 Low found and **FIXED** (`/admin/whoami` mislabeled an SSO session as `admin-console`); 2 Low accepted (deprecated `authlib.jose` import; hardcoded `groups` claim — ADR §13.3 deferral). No cross-tenant escalation, no auth bypass, no secret leak.
- **Date:** 2026-06-21
- **Auditor:** security-auditor (independent red-team, Opus — did not write this code; actively attempted to break it). Remediation of the Medium + the whoami Low by the F-014 builder, with regression tests.
- **Scope:** the most security-critical surface since F-012a. The full F-014 uncommitted diff: `src/admin/sso/**` (auth boundary, OIDC, SAML, secret-box, session, login, routes, audit), `src/admin/scope.py`, `src/admin/auth.py`, `src/admin/util.py`, `src/admin/router.py`, the five new repositories + four migrations (`0014`–`0017`), `src/persistence/hash_chain.py` + `audit_log_repository.py` (`actor_id`), `src/persistence/models/{sso_identity,events_audit_log}.py`, `src/gateway/main.py` router wiring, `contracts/{openapi.yaml,events.schema.json,ids.md}`, and the Next.js SSO surface (`frontend/src/lib/{bff,session,session-token}.ts`, `frontend/src/app/{api/,}sso/**`).

A cross-tenant escalation on this surface is product-ending; the audit was run at that bar. SAML received the heaviest scrutiny per the dispatch.

## Methodology
Adversarial review against ADR-0017's hard rules (R1–R9) and the canonical 16-vector threat model (§12). Probed: cross-tenant IdP injection / tenant-pin bypass (R1), SAML signature-wrapping/XSW + unsigned-assertion + condition-bypass + replay (R3/D5), OIDC state/nonce/PKCE/JWKS/alg-confusion (D4), fail-open group→role (R4), IdP-secret exposure across response/log/audit (R6), break-glass preservation + mutual exclusivity (R5), session-token forgery / fixation / browser-exposure (R7), hash-chain backward-compat for the new `actor_id` column, and R2/R8 freeze of `/v1` + engine logic. Empirical confirmation: ran the F-014 threat-model suites + full `tests/admin tests/compliance tests/persistence` (**417 passed** at audit time), a runtime alg-confusion probe against authlib, a custom probe of the break-glass route under an SSO session, and `semgrep --config p/python --config p/security-audit --config p/secrets --severity ERROR` over the F-014 surface (**0 findings**).

## 16-vector results

| # | Vector | Result | Controlling code (file:line) |
|---|---|---|---|
| 1 | IdP A asserts an identity into tenant B | **HOLD** | `scope.py:81-84` tenant-pin (`admin_auth.tenant_id != path tenant_id → 403`); `login.py:99-107` binds to idp_config owner; RLS layer 2 `get_tenant_session`. Empirical `test_operator_session_authz.py` + `test_sso_tenant_isolation_threat_model.py`. |
| 2 | wrong audience/issuer accepted | **HOLD** | OIDC `oidc.py:364-371` (`iss`/`aud`) + tenant from transaction owner; SAML `saml.py:215-217,470-476` (Issuer/Audience strict + owner binding). Never token-derived. |
| 3 | tenant reads another tenant's IdP config | **HOLD** | RLS on `idp_config` (migration `0014` NOBYPASSRLS + NULLIF GUC) + `caller_tenant_id` guard (`idp_config_repository.py`). Empirical `test_sso_rls_isolation.py`, vector 3. |
| 4 | SAML signature-wrapping (XSW) | **HOLD** | Delegated to python3-saml `process_response` (`saml.py:431`); strict=True + single-validated-assertion; InResponseTo re-assert. No hand-rolled XML (R3). |
| 5 | unsigned SAML assertion accepted | **HOLD** | `wantAssertionsSigned=True` (`saml.py:232`); `_classify_errors` → `SamlUnsigned`. |
| 6 | expired / NotBefore SAML | **HOLD** | strict timestamp validation; `_classify_errors` → `SamlTimeInvalid`. |
| 7 | SAML replay / InResponseTo mismatch | **HOLD** | single-use consume FIRST (atomic `UPDATE...RETURNING`) + `rejectUnsolicitedResponsesWithInResponseTo` + re-assert. |
| 8 | wrong Recipient/Destination | **HOLD** | ACS rooted at configured `sp_acs_url`; compared under strict. |
| 9 | OIDC state mismatch (CSRF) | **HOLD** | single-use consume (atomic). |
| 10 | OIDC nonce replay | **HOLD** | `nonce` bound server-side, checked; single-use state. |
| 11 | OIDC token not signed by IdP JWKS | **HOLD** | authlib alg-allow-list vs JWKS. Verified: `alg=none` → rejected; HS256 alg-confusion structurally impossible. |
| 12 | OIDC iss/aud/exp not validated | **HOLD** | `oidc.py:364-380`; 30s symmetric skew (not a grace window). |
| 13 | OIDC PKCE not enforced | **HOLD** | `code_verifier` always sent at exchange; S256 challenge. |
| 14 | unmapped group granted access | **HOLD** | `resolve_role` None on no/empty mapping; `login.py` emits `operator_sso_denied` once + raises, no provisioning. |
| 15 | break-glass broken or unaudited | **HOLD** (after MED-1 fix) | `auth.py` env-token constant-time; `breakglass_routes.py` emits distinct event; **`reject_sso_global` now gates the route so only break-glass can emit it**. |
| 16 | dishonest SSO attribution | **HOLD** | `login.py` real tenant + `operator-sso` slug + `actor_id`=admin_users.id; hash-chain opt-in-when-present. Backward-compat verified. |

Auth boundary (mutual-exclusivity, fail-closed), RLS isolation (app-layer `caller_tenant_id` + DB RLS), tenant-pinning, single-use replay stores (atomic), secret encrypt-at-rest (AES-256-GCM, fresh per-call nonce, fail-closed key load), metadata-only secret projection, fixation rotation, and hash-chain backward-compat are all sound. **No High/Critical findings.**

## Findings

### MEDIUM (FIXED) — SSO operator-session could forge a system-scoped `admin_breakglass_used` audit event
`src/admin/sso/breakglass_routes.py` — `breakglass_router` carried no scope dependency and is mounted under `admin_router` whose only guard is `require_admin`, which after F-014 accepts EITHER the break-glass env token OR an SSO operator-session. Unlike `tenants_router` (which carries `Depends(reject_sso_global)`), the break-glass route did not — so an ordinary SSO operator (any tenant, role `tenant_admin`) could `POST /admin/breakglass/login` and append an `admin_breakglass_used` row (`tenant_id=WILDCARD_UUID`, `agent_id=admin-console`, `action_taken=logged`) to the tamper-evident chain. **Empirically confirmed** at audit time: an operator-session → 200 `{"ok":true}` + 1 forged row. This contradicts ADR-0017 §8 D7 and the §12 vector-15 invariant. Impact: audit-integrity / attribution forgery on the most security-sensitive event type (false break-glass alarms, signal dilution, casting suspicion on the break-glass holder). NOT cross-tenant data access / privilege escalation / secret leak (the row is system-scoped, carries no tenant data) — hence Medium.
- **Fix (applied):** `breakglass_router` now declares `dependencies=[Depends(reject_sso_global)]` (mirrors `tenants_router`). An SSO `kind` → 403; only the env-token break-glass principal emits `admin_breakglass_used`. `require_admin` still 401s an absent/invalid token at the parent router.
- **Regression test (added):** `tests/admin/test_sso_authz_threat_model.py::test_breakglass_rejects_sso_session` — operator-session → `POST /admin/breakglass/login` → 403 AND zero `admin_breakglass_used` rows. Green.

### LOW (FIXED) — `/admin/whoami` reported `admin-console` for an SSO operator-session
`src/admin/router.py` — `whoami` returned the constant `ADMIN_PRINCIPAL` regardless of the authenticated kind, mislabeling an `operator-sso` principal as the cross-tenant break-glass identity (attribution-honesty defect; no privilege gained — the route returns only a string and reads no data).
- **Fix (applied):** `whoami` now returns `getattr(request.state, "admin_principal", ADMIN_PRINCIPAL)` — the real slug (`admin-console` for break-glass, `operator-sso` for an SSO session).
- **Regression test (added):** `test_whoami_reports_true_principal` — break-glass → `admin-console`, SSO session → `operator-sso`. Green.

### LOW (ACCEPTED) — deprecated `authlib.jose` import path
`src/admin/sso/oidc.py:51` — `from authlib.jose import JsonWebToken` emits `AuthlibDeprecationWarning` (authlib recommends `joserfc`; compatible until authlib 2.0.0; pin is `authlib>=1.3,<2`). No security impact — the alg-allow-list + JWKS verification are correct and alg-confusion-safe (verified at runtime). Disposition: supply-chain follow-up to migrate to `joserfc` before the 2.0 bump.

### LOW (ACCEPTED, ADR §13.3 deferral) — IdP groups claim/attribute hardcoded to `groups`
`src/admin/sso/oidc.py` / `src/admin/sso/saml.py` — an IdP that emits group memberships under a differently-named claim/attribute resolves to an empty group list and is **fail-closed denied** (never silently granted). Documented v1 limitation in ADR §13.3, fail-safe direction.

## Semgrep
`semgrep --config p/python --config p/security-audit --config p/secrets --severity ERROR` over the F-014 surface (`src/admin/sso`, `src/admin/scope.py`, `src/admin/auth.py`, `src/persistence/hash_chain.py`, the four new repositories): **0 findings, 0 scan errors.** No XML-parsing finding (XML signature handling delegated to python3-saml, not hand-rolled — R3); no crypto-misuse finding (AES-256-GCM via `cryptography` AEAD, fresh per-call nonce); no hardcoded-secret finding (all secrets env-loaded, fail-closed; test fixtures runtime-assembled).

## Crypto / supply-chain notes
- **Operator-session HMAC** (`session.py`): constant-time compare, expiry + `exp<=iat` rejection, fixed `auth_method="sso"` discriminator, fail-closed secret load, distinct `SENTINEL_ADMIN_SESSION_SECRET`. Sound.
- **`secret_box`** (AES-256-GCM): fresh 12-byte `os.urandom` nonce per encrypt, fail-closed key load (unset / bad-base64 / wrong-length all cached-fail-closed), `InvalidTag` surfaced. No nonce reuse. Sound.
- **Single-use stores** (OIDC/SAML transactions): atomic `UPDATE ... WHERE consumed_at IS NULL AND expires_at > now() ... RETURNING` — concurrency-safe, no TOCTOU. Privileged global session; no sentinel_app grant. Sound.
- **OIDC JWT**: alg-allow-list excludes `none`; HS256 alg-confusion structurally blocked by authlib. Verified at runtime.
- **Pins** (`pyproject.toml`): `authlib>=1.3,<2` (1.7.2 installed), `python3-saml>=1.16,<2` (1.16.0) in the `[saml]` extra (lazy-imported), `cryptography>=42,<50`. python-jose retained only for F-008 ES256, not used in F-014 OIDC (correctly avoided).

## R2/R8 freeze
Only `src/gateway/main.py` changed outside the admin/persistence SSO surface — an additive import + `app.include_router(sso_login_router)`; no `/v1` path, no security-middleware weakening, no F-003/005/008/011/012a engine edit. CORS stays `allow_credentials=False` + allow-list (default `[]`), so `/admin/sso/*` callback responses are not cross-origin browser-readable. Migration head pinned at `0017`. Hash-chain `actor_id` is opt-in-when-present, preserving all pre-F-014 row hashes (`validate_chain` passes over mixed datasets; F-012a break-glass tests intact).

## Verdict
**PASS.** 0 Critical, 0 High. The cross-tenant defense (R1) — tenant-pin at the API edge plus RLS at the DB — holds on every per-tenant route and is empirically proven for vectors 1–3; SAML (XSW/unsigned/conditions/replay) and OIDC (state/nonce/PKCE/JWKS/alg-confusion) validation are robust and delegated to vetted, pinned libraries (no hand-rolled XML/JWT, R3); IdP secrets are AES-256-GCM-at-rest and never reach the browser/logs/audit (R6); group→role is fail-closed (R4); break-glass is preserved, distinctly audited, and now mutually exclusive with SSO at the break-glass route (MED-1 fixed); the operator-session and frontend cookie spine are sound; and the `actor_id` hash-chain change is backward-compatible. The one Medium and the whoami Low are fixed with regression tests; the two remaining Lows are accepted, documented residuals with no cross-tenant or fail-open exposure. No item escalates to the human gate as an open High/Critical.
