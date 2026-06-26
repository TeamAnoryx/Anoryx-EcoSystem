# ADR-0003 — Rendly Authentication (OAuth2 + JWT) (R-003)

- **Status:** Proposed (awaiting Affu approval)
- **Date:** 2026-06-26
- **Task:** R-003 (third Rendly task; the FIRST Rendly implementation task)
- **Scope:** The self-contained OAuth2 + JWT auth service: real ES256 access-token mint + verify,
  a rotating refresh flow with reuse-detection, RFC 7009 revoke, and a narrow `UserStore` seam
  with an in-memory fixture impl. **No database, no migration, no DDL** (those are R-004). Per-
  channel RBAC enforcement is R-005/R-006 — R-003 proves identity and carries the role in the
  token; it does not enforce channel access.
- **Depends on:** merged **R-001** (the LOCKED wire contract — `contracts/openapi.yaml`,
  `contracts/ids.md`, ADR-0001) and merged **R-002** (the domain types — `src/rendly/`, ADR-0002).
- **Numbering:** Rendly-scoped sequence (Rendly ADR **0003**, following 0002). Each product
  subtree keeps its own decision record; Rendly does not extend any global sequence.
- **Deciders:** api-architect (owns `contracts/**`; consulted on surfaced point S1),
  security-auditor (independent penultimate gate — this is a security task), Affu (solo founder &
  product owner — resolved the STEP-0 forks during planning: **A+D = ES256 / env-injected,
  fail-closed**; **B+E = short access + rotating refresh w/ reuse-detection / in-memory store
  seam**; **C = Argon2id now, behind the seam**; **S1 = conform, no `aud`**; **S2 = fixture-backed
  `GET /users/me` as the proof route**).

---

## 1. Context

R-001 LOCKED Rendly's self-contained OAuth2 + JWT scheme on the wire (`/auth/token`,
`/auth/revoke`, the `TokenResponse` shape, the `AccessTokenClaims` claim set, the 8 scopes, the
fixed-message `Error` envelope). R-002 LOCKED the domain types (`User`, `Profile`, `Tenant`,
`OrgRole`, `Membership`) and made cross-tenant isolation a structural property. R-003 is the first
task that runs code: it **implements exactly that scheme against those types**. It does not
re-architect either — where implementation pressure met a contract gap, the gap was surfaced (S1),
not silently patched.

R-003 exists so the next builders proceed with no further questions: R-004 implements the
`UserStore` against the real database (no contract change), and R-005 reads identity + role off the
verified token. The contract is the law; the R-002 types are imported, never redefined.

---

## 2. Decisions (the STEP-0 forks)

### FORK A + D — ES256 (asymmetric), env-injected key, fail-closed — security-sensitive
The access token is an **ES256 (ECDSA P-256) JWT**. The R-001 contract example access token
literally decodes to `{"alg":"ES256"}`, and the whole ecosystem signs ES256 (Sentinel F-008
`policy/crypto.py`: alg pinned, header `alg` checked before the key is used). Asymmetric gives
public-key verification (rotation-friendly; what R-005+/O-010 multi-service verification needs) and
keeps the private key on the issuer. Verification uses **PyJWT** with an explicit
`algorithms=["ES256"]` allowlist (banked ecosystem rule: *no hand-rolled JWT/signature
verification*). The signing **private key** is injected from `RENDLY_JWT_PRIVATE_KEY_PEM` at
startup and validated to secp256r1; **absent / empty / unparseable / wrong-curve → `KeyConfigError`
and the service refuses to start** — there is no default or in-repo key, so the token endpoint can
never sign with a fallback. The verifying public key is derived from the loaded private key (R-003
is issuer + verifier in one process).
- *Rejected (HS256 / symmetric):* one shared secret is simplest, but every verifier would hold the
  *signing* secret and could mint tokens — the wrong posture for a platform other services verify.
- *Tradeoff (accepted):* ES256 needs a P-256 keypair and key-management discipline now; that cost
  buys public-key verification and matches the contract example + the ecosystem.
- *Future seam:* key rotation / JWKS / a verify-only consumer (R-005) injecting only the public key
  — documented, not built.

### FORK B + E — short access + rotating refresh w/ reuse-detection; in-memory store seam — security-sensitive
Access tokens live **15 minutes** (well under the contract's 1-hour ceiling), limiting stolen-token
blast radius. The contract MANDATES refresh rotation ("rotate on each refresh") and makes the
refresh token an **opaque** handle (`rt_<...>`, not a JWT), which implies server-side state.
R-003 implements that state behind a narrow `RefreshTokenStore` seam:
- **Rotation:** each refresh consumes the presented token and issues a successor in the same
  *family* at the next generation.
- **Reuse-detection:** presenting an already-used token (a replay) revokes the **whole family**, so
  a stolen-then-replayed token also burns the thief's freshly-minted one.
- **Revocation (`/auth/revoke`):** revokes the presented token's family; idempotent (an
  unknown/already-revoked token is a silent no-op — no existence leak).
- **Hashed at rest:** only the SHA-256 of each opaque token is stored, so a store dump yields no
  usable tokens.
- *Rejected (longer access + stateless refresh):* simpler, but cannot do reuse-detection or revoke,
  and the contract's opaque `rt_` shape + `/auth/revoke` both assume server state — stateless would
  contradict the locked contract.
- *Storage (E):* the in-memory impl is per-process and lost on restart — the **documented R-004
  seam**. R-004 implements `RefreshTokenStore` against the database with no contract change.

### FORK C — Argon2id credential hashing now, behind the seam
Credentials are verified with **Argon2id** (`argon2-cffi`, the ecosystem + OWASP standard;
Sentinel stores Argon2id PHC strings). The `UserStore` returns a stored PHC hash and R-003 verifies
constant-time. This sets the exact pattern R-004 inherits for the DB — only the *lookup* is
fixture-backed, never the hashing.
- *Rejected (defer to R-004 / plaintext fixture compare):* keeps R-003 "purely about tokens" but
  ships a credential path R-004 must retrofit and banks a plaintext compare in the auth path.
- *Property:* a bad username, a wrong password, and a malformed stored hash all yield the SAME
  generic 401 `invalid_token` (no user-enumeration oracle).

### S1 (surfaced contract point) — NO `aud` claim: conform to the locked, closed `AccessTokenClaims`
The dispatch listed `aud` among the registered claims and asked for a "wrong aud → 401" test, but
the LOCKED `AccessTokenClaims` is closed (`additionalProperties:false`) and **omits `aud`** —
adding it would violate the schema and fail conformance. This was surfaced, not silently resolved.
For a single self-issued audience (Rendly's own API), `iss` (const `https://rendly.anoryx.io`) +
`token_use` (const `access`) bind issuer and purpose. Verification therefore checks signature,
`exp`, `iss`, and `token_use` (the `token_use` Literal in the closed claims model blocks
refresh-as-access confusion). The adversarial "wrong audience" case becomes **wrong `iss` / wrong
`token_use` → 401**.
- *Rejected (treat `aud` as required):* that is an R-001 contract change (api-architect edits
  `AccessTokenClaims`); heavier and, for a single-service self-issued token, unnecessary. If a
  future multi-audience need arises, it goes through the contract-change process, not R-003.

### S2 (surfaced scope point) — fixture-backed `GET /users/me` as the protected proof route
R-003 needs one protected route to prove the verify dependency authorizes end-to-end.
`GET /users/me` is contract-defined (returns `User`, requires `profile:read`), is the canonical
identity proof, and demonstrates scope enforcement. It is backed by the fixture `UserStore`; R-004
takes it over (and the rest of the `/users` surface) with no contract change. Identity is read from
the verified token, never from request input.
- *Rejected (a non-contract internal probe):* avoids touching an R-004-tagged path but proves less
  of the real surface.

---

## 3. Reconciliation with the contract (R-001 wins on any conflict)

| Topic | Dispatch working language | R-001 LOCKED (used) |
|---|---|---|
| Token error shape | (unspecified) | Rendly `Error` envelope, NOT the RFC 6749 error object (ADR-0001 D2) |
| Registered claims | includes `aud` | `AccessTokenClaims` is closed and has **no `aud`** (S1: conform) |
| Token `roles` | "the role enum {admin,member,guest}" | the tenant-level `OrgRole = {admin,member,guest}` (R-002), carried in the open `roles` array — **not** the channel `ChannelRole` (which has `owner`) |
| Refresh token | (unspecified) | opaque `rt_<...>`, rotate on each refresh |
| Module name | `auth/jwt.py` | `auth/tokens.py` — renamed so it never shadows the PyJWT package it imports |

No field R-001 did not expose is added to any wire shape. The error `message` is fixed 1:1 by
`error_code` (R-001 audit LOW-6 is now a real binding test, not a cardinality check).

---

## 4. Threat model (security focus, with test paths)

| # | Vector | Defense | Test |
|---|---|---|---|
| 1 | **Forged token** (no key) | ES256 signature verified with the public key; tampered sig → 401 | `test_tampered_signature_is_401` |
| 2 | **alg-confusion** (HS256 forged with the public key as HMAC secret) | `algorithms=["ES256"]` allowlist rejects the alg before any key use | `test_alg_confusion_hs256_with_public_key_is_rejected` |
| 3 | **`alg:none`** | same allowlist rejects `none` | `test_alg_none_token_is_rejected` |
| 4 | **Expired token** | `exp` verified; fail-closed | `test_expired_token_is_401` |
| 5 | **Wrong issuer / refresh-as-access** | `iss` const + `token_use` const verified (S1) | `test_wrong_issuer_is_401`, `test_wrong_token_use_is_401` |
| 6 | **Claim-injection** (a body field overriding tenant/role) | no auth body carries identity; closed schema → unknown key 400; identity is token-derived | `test_request_body_cannot_inject_tenant_id`, `test_issued_tenant_is_token_derived_not_request_derived` |
| 7 | **Cross-tenant** (a token acting on another tenant) | tenant is read from the token; `get_user` is tenant-scoped → a mismatched principal resolves no user → 401 | `test_cross_tenant_principal_cannot_resolve_a_foreign_user`, `test_each_token_sees_only_its_own_tenant_user` |
| 8 | **Refresh replay** | reuse-detection revokes the family | `test_replayed_refresh_token_is_rejected`, `test_reuse_revokes_the_whole_family` |
| 9 | **Credential brute-force surface / enumeration** | Argon2id constant-time verify; unknown user, wrong password, malformed hash → same generic 401 | `test_bad_password_is_generic_401`, `test_unknown_user_is_same_generic_401` |
| 10 | **Missing signing key at deploy** | fail-closed: `KeyConfigError`, the service won't start / won't sign | `test_missing_env_fails_closed`, `test_wrong_curve_fails_closed` |
| 11 | **Internal error passing traffic through** | any unexpected error fails closed to 500 `internal_error`; never passes through | `test_internal_error_fails_closed_to_500` |
| 12 | **DoS-via-parse** | body-size cap enforced from Content-Length BEFORE parsing → 413 | `test_oversized_body_is_413` |
| 13 | **Scope widening** | a requested scope outside the granted set → 400; a token lacking the endpoint scope → 403 | `test_requesting_ungranted_scope_is_400`, `test_insufficient_scope_is_403` |
| 14 | **Log injection via jti** | `jti` charset-bounded `^[A-Za-z0-9._-]{1,64}$` (closed claims model) | (structural — `claims.py`) |

---

## 5. Honesty boundary (verbatim, non-removable)

> R-003's end-to-end test proves the REAL issue/verify/refresh path against a FIXTURE user store;
> it is NOT proven against a database. The token cryptography and the verify/refresh logic are real
> and fully tested — only the user lookup is fixture-backed. This is a stated seam, not a stubbed
> enforcement path. R-004 implements the `UserStore` against the real database with no contract
> change.

Additionally: `GET /users/me` is fixture-backed in R-003 (S2); `authorization_code`/OIDC and the
O-010 unified-identity federation are documented seams only (the `idp_subject` claim is null);
rate-limiting / lockout is noted as a follow-up, not built inline. Framing is "risk reduction" and
"audit-ready", never "blocks all attacks".

---

## 6. Consequences

- **Positive:** the real token path (issue / verify / rotate / revoke) is fully tested with
  adversarial coverage; identity is structurally token-derived (claim-injection + cross-tenant
  closed); the crypto + hashing posture matches the ecosystem; R-004 swaps the fixture stores for
  the DB with no contract change, and R-005 reads identity + role off the token with no further
  questions.
- **Negative / accepted:** the user + refresh stores are in-memory (per-process, lost on restart) —
  the documented R-004 seam; R-003 stands up the `/v1/users/me` GET route ahead of R-004's full
  `/users` surface (read-only, own principal, fixture-backed) to have a real authorization proof.
- **Naming note:** the JWT mint/verify module is `auth/tokens.py`, not `auth/jwt.py`, so it never
  shadows the imported PyJWT package.

---

## 7. CI

`.github/workflows/rendly-ci.yml` (`rendly-contracts`, path filter `Rendly/**`, Python 3.12) is
extended: the install now pulls `fastapi` + `pyjwt[crypto]` + `cryptography` + `argon2-cffi` (deps)
and `httpx` (dev, the TestClient transport); the single `pytest --cov=rendly` run executes the
R-001 contract suite, the R-002 domain suite, AND the R-003 auth suite (real ES256 issue/verify/
refresh e2e + adversarial cases) under the `fail_under=90` gate. A suite that did not run would
leave its package surface uncovered and FAIL — so the lane provably EXECUTES the auth tests, not
skips them (banked rule 4: CI authoritative). The tests self-provision an ephemeral ES256 keypair
(and exercise the env fail-closed loader via monkeypatch), so no signing secret is needed in CI.

---

## 8. Rollback

R-003 is additive: a new `Rendly/src/rendly/auth/` package + `Rendly/src/rendly/app.py`, a new
`Rendly/tests/auth/` suite, this ADR, `Rendly/docs/audit/r-003-security-audit.md`, and additive
`pyproject.toml` + `rendly-ci.yml` extensions. It adds no server entrypoint deployment, no DB, no
migration, and leaves R-001's `openapi.yaml` / `messages.schema.json` / `ids.md` and the R-002
domain modules byte-for-byte unchanged. Rollback = revert the single squashed R-003 commit; nothing
in the monorepo imports the auth package yet, so revert is clean and total.
