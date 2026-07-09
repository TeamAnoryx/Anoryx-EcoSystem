# D-017 Security Audit — RBAC-Gated Dashboards: Locally-Issued Role-Tagged Access Tokens

- **Date:** 2026-07-09
- **Scope:** `Delta/src/delta/rbac/` (the entire new package), `Delta/src/delta/persistence/
  migrations/versions/0011_rbac_access_tokens.py` (new `access_tokens` table, RLS, grants,
  CHECK constraints), the additive-only changes to `Delta/src/delta/identifiers.py` and
  `Delta/src/delta/persistence/models.py`, the one new router mount in
  `Delta/src/delta/allocation_admin/app.py`, **`Delta/src/delta/dashboards/router.py`**
  (the one existing file this task modifies — the router-level auth dependency), `Delta/
  tests/rbac/`, the new frontend surface (`Delta/frontend/src/app/(admin)/rbac/`, `Delta/
  frontend/src/components/rbac/`, and the additive changes to `types.ts`/`admin-client.ts`/
  `bff.ts`/`app-nav.tsx`), and `Delta/docs/adr/0017-delta-rbac-dashboards.md` (the design
  record, cross-checked against the actual shipped code).
- **Reviewer:** independent security-auditor pass (arms-length from the implementer, per
  banked process rule #3 — re-run against the code, not implementer-self-verified). Given
  this is a NEW authentication/authorization surface — the first genuine auth mechanism
  Delta has added since D-007's original break-glass bearer — this review received the
  highest scrutiny of any task in this session: 10 prioritized adversarial attack vectors
  (auth bypass, token entropy/collision, timing attacks, privilege escalation, cross-tenant
  RLS leakage under 40-way concurrency, the dashboards-retrofit regression risk, a
  revocation-race check, a self-bootstrap-abuse check, frontend token handling, and input
  validation), each exercised against the live database and a real running ASGI app, not
  assessed by code review alone. A Semgrep-equivalent local ruleset was also run (the
  registry fetch was blocked by the environment's egress policy, the same known limitation
  recorded in every prior audit this session).
- **Verdict:** **CLEAN** — no High or Critical findings. Three Low findings, all of which
  are honest, already-documented residual-risk notes in ADR-0017 §3, not defects
  introduced by this diff — none block merge, no code changes made.

## What was actively tried and found sound

- **Authentication bypass (vector 1).** No request reaches a protected route without a
  valid bearer: an empty bearer, a wrong auth scheme, a missing `tenant_id`, and a bogus
  token were all tried against both `/rbac/*` and the retrofitted `/dashboards/*` and all
  correctly returned 401/422. The `require_role`/`tenant_id`-sharing composition between
  the router-level `Depends()` and each route handler was verified to resolve to the SAME
  value in every case — no FastAPI edge case allowed a mismatch.
- **Token entropy / collision (vector 2).** `secrets.token_urlsafe(32)` produces a 43-
  character, 256-bit-entropy value — cryptographically unpredictable, not seedable from
  anything request-observable. SHA-256 storage of that high-entropy value is standard and
  appropriate; the `UNIQUE` constraint on `token_hash` is a correctness backstop, not a
  security-load-bearing one (collision is not a practical concern at this entropy).
- **Timing attacks (vector 3).** The break-glass path uses `hmac.compare_digest`
  (constant-time) exactly as `require_admin` already did. The issued-token path is an
  indexed, exact-match SQL `WHERE token_hash = :hash` lookup — no application-layer
  byte-by-byte comparison exists to leak timing information about a partial hash match.
- **Privilege escalation (vector 4).** A `tenant_auditor` token was tried against every
  `tenant_admin`-gated action (list tokens, create a token — including attempting to
  create one at `tenant_admin` role for itself, revoke a token) and rejected with 401 in
  every case. `role_at_least` fails closed for any unrecognized role string.
- **Cross-tenant RLS leakage (vector 5).** Verified directly against the database AND
  under 40-way concurrent load: a token issued for tenant A resolves to `None` when
  looked up inside a tenant-B-scoped session — zero cross-tenant leaks, zero false
  negatives on the token's own tenant. The RLS GUC (`app.current_tenant_id`) was
  confirmed transaction-local with no leakage across pooled connections (the D-013-era
  "session reused across two commits" bug class was specifically checked for and not
  present — every mutating call in `delta.rbac.service` opens its own `get_tenant_session`
  block).
- **The dashboards retrofit regression (vector 6).** Confirmed via actual test runs, not
  just reading: the break-glass token still returns 200 on every dashboards route
  post-retrofit; no dashboards route lost its auth gate; nothing downstream depended on
  the `admin_principal` value `require_admin` used to set (the retrofit is a genuinely
  clean swap).
- **Revocation race (vector 7).** `revoke_token`/`get_active_token_by_hash` were checked
  for a TOCTOU gap (the bug class D-015's audit found elsewhere in this session) — this
  is a single-statement read of already-committed state with no check-then-use window;
  not a reproducible race.
- **Issuance self-bootstrap abuse (vector 8).** A tenant-A-scoped issued token cannot
  influence issuance for tenant B by any path tried — every `rbac` route re-derives its
  authorization from the presented bearer alone, never from a prior request's context.
- **Frontend token handling (vector 9).** The raw token lives only in
  `create-token-form.tsx`'s React component state (the one-time reveal, cleared on
  acknowledgment) — no `console.log`, `localStorage`, or cookie write anywhere in the
  reveal path. `admin-client.ts` remains `server-only`; `bff.ts`'s traversal guard and
  `encodeURIComponent` usage are intact for the new `"rbac"` root.
- **Input validation (vector 10).** `extra="forbid"` rejects unexpected fields (422); the
  DB `CHECK (role IN ('tenant_admin', 'tenant_auditor'))` constraint was confirmed as a
  genuine backstop by attempting an invalid role via a privileged, Pydantic-bypassing
  direct INSERT — rejected at the database layer, not just by the API schema.

## Findings

| # | Severity | Location | Issue | Resolution |
|---|---|---|---|---|
| 1 | Low | `frontend/src/lib/bff.ts` (adding `"rbac"` to `ALLOWED_ROOTS`) | The BFF injects the break-glass `DELTA_ADMIN_TOKEN` for any authenticated frontend session, and break-glass is implicit `tenant_admin` for every tenant — so any logged-in operator can mint `tenant_admin` tokens for ARBITRARY tenants through the frontend. This is not a D-017 regression (the identical trust model already applies to every other admin surface reachable through the BFF — allocations, crm, erp, etc.), but RBAC is the one surface where the consequence is literally credential issuance, so it is flagged for awareness even though no fix is required to merge. | **Accepted as by-design**, matching ADR-0017 Fork 2/7's own stated trust boundary (the break-glass bearer is intentionally cross-tenant and always at least `tenant_admin` — this is the documented bootstrap mechanism, not an oversight). When real per-operator identity lands (F-014 federation, ADR-0017 §3's named future work), `/rbac` specifically should be reconsidered for a stronger session assertion than the shared break-glass injection. No code change made. |
| 2 | Low | `rbac/service.py` (`create_token`/`revoke_token`, no audit-chain wiring) | Token issuance/revocation are not written to D-009's hash-chained audit log, so there is no attributable record of who minted or revoked a credential (a token's `name` is an operator-chosen free string, not a verified identity). | **Already named as a deliberate deferral** in ADR-0017 §3 ("No in-app audit trail for token issuance/revocation... mirrors D-013/D-015's reasoning"), consistent with D-009's own stated scope (Delta's automated FINANCIAL workflows — an access-control action is not one). Recommended as a real future improvement before this surface leaves its current bounded scope, not a merge blocker. No code change made. |
| 3 | Low | `rbac/service.py` (`create_token`, no TTL field) | Issued tokens have no expiry/rotation — valid until explicitly revoked. A leaked token (shell history, CI logs, a screenshotted one-time reveal) remains a valid bearer indefinitely with no automatic backstop. | **Already named as a deliberate deferral** in ADR-0017 §3 ("No token expiry/rotation policy... mirrors D-007's own break-glass token's existing residual risk, noted honestly there too"). A future `expires_at` column + an updated `get_active_token_by_hash` predicate is the concrete fix path when prioritized. No code change made. |

## Threat model cross-reference

See `docs/adr/0017-delta-rbac-dashboards.md` §4 for the full vectors-to-mitigations-to-
tests table this audit validated against (cross-tenant isolation, break-glass backward
compatibility, revoked-token rejection, privilege escalation, raw-token exposure, fail-
closed unknown-role handling, auth-bypass coverage, input validation) — every row in that
table was independently re-verified here, not merely cross-checked against the ADR's own
claims.

## Honesty boundary (carried from the ADR, restated for the audit record)

This review covers only the D-017 RBAC surface (plus the one retrofitted file,
`dashboards/router.py`) listed under Scope above. It does not re-audit
`allocation_admin.auth.require_admin` or `delta.persistence.database.get_tenant_session`
(both unchanged, already audited across D-007/D-009's own audit records) — D-017 reuses
both unmodified and this review confirmed it does so correctly. It also does not attempt
to audit Anoryx-Sentinel's own F-014/ADR-0017 (a different product's already-shipped,
independently-audited feature) beyond reading its role vocabulary for naming consistency.
Per ADR-0017 §1/§3, this is a deliberately bounded vertical slice of the roadmap's
"org-tier-scoped dashboards" — this review assessed the code as the bounded slice it
claims to be (a local, token-based two-role model gating one existing surface), not
against real SSO/OIDC/SAML federation or a retrofit across Delta's other six admin
surfaces, both of which this task explicitly and honestly declines to build.
