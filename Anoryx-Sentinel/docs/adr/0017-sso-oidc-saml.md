# ADR-0017 — SSO (OIDC + SAML) for the Admin Console (F-014)

- **Status:** Proposed
- **Date:** 2026-06-21
- **Deciders:** (admin/SSO owner / implementer), api-architect (contract — `openapi.yaml` SSO + admin-identity endpoints, `events.schema.json` four new variants + the `actor_id` attribution field, `ids.md` new `operator-sso` slug), persistence (migrations `0014`/`0015`, `events_audit_log` constants + the new nullable `actor_id` column, the new RBAC + IdP-config + group-mapping tables and their RLS policies), security-auditor (HEAVY adversarial gate — this is the most security-critical feature since F-012a; SAML especially), Affu (solo founder & product owner — resolved the STEP-0 forks during planning: **Fork 1 = (b) RBAC** identity model with the admin API authoritative (Authz Model 2); **Fork 2 = authlib (OIDC) + python3-saml (SAML)**; **Fork 3 = OIDC first, then SAML**; **Fork 4 = SP-initiated only, signed assertion required, unsigned rejected**; **Fork 5 = one IdP per tenant per protocol (v1)**; approves this ADR at the STEP-1 gate).
- **Supersedes / amends:** Builds **on top of** and **does not modify** ADR-0003 (persistence / hash-chain audit — F-014 **appends** SSO/break-glass meta-events via the existing append-only writer and **adds one nullable content column** `actor_id` to `events_audit_log`, folded into the hash-chain canonical form; it never mutates existing rows and never rewrites the chain), ADR-0005/0006 (tenant isolation / RLS Option α — F-014 **reuses** `get_tenant_session(TARGET)` for all new tenant-scoped tables and the `get_privileged_session()` break-glass path only for the global `tenants` registry and chain append; **no new BYPASSRLS path**), ADR-0009 (F-008 env-secret + load-once crypto pattern — F-014 mirrors it for the IdP-secret encryption key and the operator-session secret), ADR-0014 (F-012a admin API — F-014 **builds the identity layer ADR-0014 §13.3 explicitly deferred**: the env token is KEPT as break-glass, not replaced; `require_admin` gains an additive SSO branch), ADR-0015 (F-012 console session spine — F-014 **reuses** the signed httpOnly cookie + middleware + login route; it adds an SSO login path and carries an admin-API-issued operator-session inside the same cookie spine, no parallel session). Governed by `contracts/openapi.yaml`, `contracts/events.schema.json`, `contracts/ids.md`. **The contracts win over this ADR on any conflict.**
- **Feature:** F-014 — **SSO (OIDC + SAML) for human operators on the admin surface only.** It adds the deferred admin identity + role layer (RBAC), per-tenant IdP configuration with encrypted-at-rest secrets, OIDC and SAML assertion validation, per-tenant group→role mapping (fail-closed), and an audited env-token break-glass. The `/v1` data plane (virtual API keys, machine auth) is **untouched** (R2).

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)

- **Admin auth** (ADR-0014, `src/admin/auth.py:47`): a single deploy-injected
  `SENTINEL_ADMIN_TOKEN`, validated by `require_admin` with `hmac.compare_digest`,
  fail-closed (unset/empty → 401, no tenant fall-through). The sole admin principal is
  the reserved slug `agent_id="admin-console"`. **There are no operator identities, no
  roles, no DB principal** — ADR-0014 §13.3 deferred all of it; F-012a's security audit
  (LOW, line 53) named multi-operator + per-operator attribution as the upgrade path.
- **Cross-tenant access** (ADR-0014 D2): an operator names the target tenant in the URL
  path and the service opens `get_tenant_session(TARGET)`; RLS stays in force, one named
  tenant per request. The global `tenants` registry uses `get_privileged_session()`. The
  F-012a HIGH fix `_assert_scope_in_tenant` (`src/admin/keys.py:38`) is the precedent for
  binding caller-supplied scope to the target tenant.
- **RLS** (ADR-0005/0006): `get_tenant_session(tenant_id)` (`database.py:250`) sets the
  transaction-local GUC `app.current_tenant_id` on the NOBYPASSRLS `sentinel_app` role;
  `NULLIF(current_setting(...),'')` fail-closes to zero rows. New tenant-scoped tables
  copy this RLS pattern.
- **Audit 4-site discipline**: `VALID_EVENT_TYPES` (`events_audit_log.py:40`) +
  `ACTION_TAKEN_BY_EVENT_TYPE` (`:88`), `ck_eal_event_type` (head **`0013`**),
  `contracts/events.schema.json` (`oneOf` + per-variant `const`). Admin meta-events are
  appended by `emit_admin_event` (`src/admin/audit.py:51`) with honest attribution rules
  in `contracts/ids.md`.
- **Console session spine** (ADR-0015): `frontend/src/lib/session-token.ts` signs a
  payload `{iat,exp,principal}` with HMAC-SHA256 under a **separate** `SESSION_SECRET`;
  `session.ts` sets the `admin_session` cookie (httpOnly, secure, SameSite=strict, 30 min);
  `app/api/login/route.ts` is the Fork-A break-glass login (token→cookie); `lib/bff.ts`
  proxies `/admin/*` and injects `SENTINEL_ADMIN_TOKEN` server-side (never in the browser).
- **Crypto** (ADR-0009, `src/policy/crypto.py`): a load-once, fail-closed env-keyed
  signing module (ES256 JWS). There is **no symmetric encrypt-at-rest helper** today, and
  **no SAML library**; `python-jose[cryptography]` + `cryptography` are present.

**The key tension (vector 16).** The audit event has fixed columns and a LOCKED `agent_id`
slug; **there is no field that can carry a per-operator identity.** Honest SSO attribution
therefore requires either a new event field or a side table. We choose a new field (D9).

### 1.2 Decision (one paragraph)

We add an **SSO identity layer** under `src/admin/sso/` (new) and extend `src/admin/`,
keeping every existing primitive intact. **Identity = RBAC (D1, Fork 1b):** three new
RLS-scoped tables — `admin_users` (per-tenant operator identities keyed by
`(tenant_id, idp_subject)`), `admin_roles` (a small seeded role set), and
`admin_role_assignments` ((tenant, user)→role) — so an SSO subject resolves to a real,
tenant-scoped, role-bearing principal. **The Python admin API is authoritative (D2, Authz
Model 2):** after assertion validation it mints a **signed operator-session** (HMAC-SHA256
under a new env secret `SENTINEL_ADMIN_SESSION_SECRET`, payload = tenant + admin_user_id +
role + auth_method + iat/exp/jti) which the console carries inside the existing F-012 cookie
spine; the admin API independently **verifies** it and **enforces the operator's
tenant-pin + role** on every call. The operator-session is **tenant-pinned** — an operator
authenticated via tenant A's IdP can act only on tenant A (**this is the cross-tenant
defense, R1**); the env `SENTINEL_ADMIN_TOKEN` remains a **separate, cross-tenant
break-glass** path, audited distinctly. **Per-tenant IdP config (D3)** lives in an
RLS-scoped `idp_config` table; OIDC `client_secret` and SAML private material are
**encrypted at rest** with a new symmetric helper (`cryptography` AES-256-GCM, key from
`SENTINEL_IDP_SECRET_KEY`, load-once/fail-closed mirroring `policy/crypto.py`) and are
**never returned to the browser, never logged, never written to audit rows** (R6).
**OIDC (D4):** `authlib`, authorization-code + **PKCE**, validating `state`, `nonce`,
`iss`, `aud`, `exp`/`iat`, and the signature against the IdP **JWKS**. **SAML (D5):**
`python3-saml` (optional extra `[saml]`; deploy adds `libxmlsec1`), **SP-initiated only**,
**signed assertion required, unsigned rejected**, validating Issuer / Audience / Recipient /
Destination / NotBefore / NotOnOrAfter / **InResponseTo** (replay). **Group→role (D6):** a
per-tenant `idp_group_role_map`; an IdP group with no mapping grants **no access**
(fail-closed); an unmapped/unknown subject is **denied**. **Break-glass (D7):** the env
token is preserved, audited via a distinct `admin_breakglass_used` event; global
tenant-registry mutations stay break-glass-only in v1 (no SSO path is cross-tenant).
**Console (D8):** the F-012 spine is reused; the session is **rotated on login**
(fixation guard, R7); the BFF presents the operator-session for SSO sessions and the env
token for break-glass. **Events (D9):** four new variants
(`operator_sso_login`, `operator_sso_denied`, `admin_breakglass_used`,
`idp_config_changed`) land 4-site, plus **one nullable `actor_id` content column** on
`events_audit_log` (the admin_user UUID — not PII, not a secret) folded into the hash-chain
canonical form, carrying honest per-operator attribution. **Persistence (D10):** two
reversible migrations — `0014` (the four new tables + RLS) and `0015` (the event-variant
CHECK widen + the `actor_id` column). No frontend SSO on `/v1`, no SCIM, one provider tested
per protocol, one IdP per tenant per protocol (honest scope §13.3).

### 1.3 What changes vs. what is frozen

| Frozen (MUST NOT change) | Changes (F-014) |
|---|---|
| `/v1` data-plane auth (virtual API keys, `AuthMiddleware`) — **R2** | **Nothing.** No SSO code path touches `/v1`. |
| `src/admin/auth.py` env-token break-glass — **R5/R8** | **Kept.** `require_admin` gains an **additive** SSO branch that accepts an operator-session bearer; the env-token branch is unchanged and stays cross-tenant break-glass. |
| F-003 hash-chain writer, append-only triggers, RLS `USING(false)` | **Not modified.** F-014 only **appends** via the existing writer and **adds one nullable content column** included in the canonical hash for new rows. |
| F-003b RLS role/GUC model | **Reused unchanged.** New tables are tenant-scoped via the standard `get_tenant_session` + RLS pattern; no new BYPASSRLS. |
| F-005/F-008/F-011/F-012a **engine logic** | **Untouched** (R8). F-014 adds an identity layer + SSO middleware + endpoints. |
| F-012 console session spine (cookie, `SESSION_SECRET`, middleware) | **Reused** (R7). SSO adds a login path + carries an admin-API-issued operator-session inside the same cookie; session rotated on login. No parallel session. |
| Existing `events.schema.json` variants | **FOUR new variants ADDED** + a new optional `actor_id` field on admin/SSO variants; no existing variant changed. |
| `ck_eal_event_type` widen pattern (head `0013`) | Migration `0015` widens it with 4 variants (DROP+ADD, reversible). |
| `contracts/ids.md` reserved values | **Additive:** new `operator-sso` slug + documented `actor_id` attribution semantics. |

---

## 2. Decision D1 — Identity = RBAC (Fork 1b): `admin_users` + roles + assignments

Affu chose fork **(b)** at STEP 0. SSO subjects become **real, tenant-scoped, role-bearing
principals**, not a single implicit admin.

1. **`admin_users`** — `id (uuid pk)`, `tenant_id (uuid, RLS)`, `idp_subject (text)`,
   `idp_config_id (fk)`, `display_name`, `is_active`, `created_at`, `last_login_at`.
   Unique `(tenant_id, idp_subject)`. The `idp_subject` is the IdP's stable subject (OIDC
   `sub` / SAML NameID), **never** a password. RLS-scoped: a tenant sees only its own users.
2. **`admin_roles`** — a small **seeded** set (not user-editable in v1):
   `tenant_admin` (manage own tenant: keys mint/rotate/revoke, config adjust, audit read,
   compliance evidence) and `tenant_auditor` (read-only: audit/config/policies view). Real
   RBAC, honestly minimal (§13.3).
3. **`admin_role_assignments`** — `(tenant_id, admin_user_id, role)`, RLS-scoped. A user
   with no assignment has **no access** (fail-closed, R4).

A subject is provisioned (a row in `admin_users` + an assignment) the first time a verified
assertion maps its group(s) to a role (D6); a subject whose groups map to nothing is denied
and **not** provisioned. All three tables copy the `get_tenant_session` RLS pattern
(NOBYPASSRLS `sentinel_app`), so cross-tenant reads of identities/roles are impossible at
the DB layer (vector 3).

---

## 3. Decision D2 — Authz Model 2: the admin API is authoritative; tenant-pinning is the cross-tenant defense

The admin API does not trust the frontend to assert identity. It is the authority.

1. **Operator-session token.** After a successful assertion validation + group→role
   resolution, the admin API mints a compact signed token: HMAC-SHA256 over a canonical
   payload `{tenant_id, admin_user_id, role, auth_method:"sso", iat, exp, jti}` under a new
   env secret **`SENTINEL_ADMIN_SESSION_SECRET`** (Vault/KMS-injected; distinct from the
   frontend `SESSION_SECRET` that signs the browser cookie and from the break-glass
   `SENTINEL_ADMIN_TOKEN`). Short TTL (≤30 min, matching the cookie). HMAC (symmetric) is
   correct here: the **same** admin API both mints and verifies — no asymmetric trust is
   needed (we do **not** reuse the ES256 policy-signing keypair, which exists for an
   external signer). Verification is constant-time and fail-closed.
2. **`require_admin` gains an additive SSO branch.** It accepts **either** an env-token
   bearer (break-glass, cross-tenant, unchanged) **or** an operator-session bearer (SSO).
   The two are distinguished by token shape and validated independently — neither falls
   through to the other (mirrors D1 of ADR-0014: a tenant key never elevates to admin).
3. **Tenant-pinning = the R1 control.** When authenticated via an operator-session, the
   admin API derives the allowed tenant from the **token**, not the URL. Any request whose
   target tenant (URL `{tenant_id}`) ≠ the token's `tenant_id` is rejected **403** before
   any session opens (vectors 1, 2). RLS is the second layer: even if pinning were bypassed,
   `get_tenant_session(token.tenant_id)` scopes every query to the operator's own tenant.
4. **Role enforcement.** Each admin route declares a required role; the operator-session's
   role must satisfy it (`tenant_auditor` is denied write routes). Break-glass (env token)
   is unconstrained by role (it is the recovery path).
5. **Global ops stay break-glass-only (v1).** Tenant-registry mutations (create/deactivate
   a tenant) are inherently cross-tenant and have **no SSO path** in v1 — they require the
   env token. This keeps the invariant *no SSO-authenticated request is ever cross-tenant*
   clean and total (R1).

---

## 4. Decision D3 — Per-tenant IdP config storage, secrets encrypted at rest

1. **`idp_config`** — `id (uuid pk)`, `tenant_id (uuid, RLS)`, `protocol ('oidc'|'saml')`,
   `is_active`, plus protocol fields: OIDC (`issuer`, `client_id`, `client_secret_enc`,
   `scopes`), SAML (`idp_entity_id`, `idp_sso_url`, `idp_x509_cert`, `sp_acs_url`,
   `audience`/SP entityID, `sp_private_key_enc` if SP-signing is configured). **One active
   config per `(tenant_id, protocol)`** (Fork 5). RLS-scoped: a tenant cannot read another
   tenant's IdP config (vector 3).
2. **Encryption at rest (R6).** A new helper `src/admin/sso/secret_box.py` wraps
   `cryptography` **AES-256-GCM**: `encrypt(plaintext)→(nonce‖ct‖tag)`, `decrypt(...)`,
   keyed by `SENTINEL_IDP_SECRET_KEY` (32-byte base64 env, Vault/KMS-injected), loaded
   **once** and **fail-closed** (set-but-invalid → startup error; unset → IdP config writes
   refuse, mirroring `policy/crypto.load_verifying_key`). The IdP signing **certificate**
   (public) is stored plaintext; the OIDC `client_secret` and any SP **private** key are
   stored only as ciphertext.
3. **Never to the browser, never logged, never in audit.** `GET` config endpoints return
   metadata + a redacted indicator (`client_secret_set: true`), never the secret or
   ciphertext. No secret/ciphertext is logged. `idp_config_changed` audit rows carry the
   config id + protocol, **never** secret material (R6).

---

## 5. Decision D4 — OIDC middleware (authlib; auth-code + PKCE; full validation)

`src/admin/sso/oidc.py`, using **authlib** (pinned). SP-initiated authorization-code flow:

1. **Initiate.** Generate a high-entropy `state` (CSRF) and `nonce` (replay) and a PKCE
   `code_verifier`/`code_challenge` (S256); persist them bound to the browser
   (short-TTL, single-use) and redirect to the tenant's `issuer` authorization endpoint
   with `code_challenge`.
2. **Callback validation (all fail-closed).** Verify `state` matches the stored value
   (vector 9); exchange the code with the `code_verifier` (PKCE — vector 13); fetch/cache
   the IdP **JWKS** and verify the ID token **signature** (vector 11); validate `iss` ==
   configured issuer, `aud` == configured `client_id`, `exp`/`iat` within skew (vector 12),
   and `nonce` matches + is single-use (vector 10). Only then read claims.
3. **Identity.** The verified `sub` is the `idp_subject`; the configured groups claim
   (e.g. `groups`/`roles`) feeds D6. The `tenant_id` is the tenant that **owns the
   `idp_config`** used — never a value from the token (this is the audience/issuer→tenant
   binding, vector 2).

---

## 6. Decision D5 — SAML middleware (python3-saml; SP-initiated; signed assertion; strict conditions)

`src/admin/sso/saml.py`, using **python3-saml** (optional extra `[saml]`; deploy image adds
`libxmlsec1`). **We do not hand-roll XML signature validation** (R3) — the library performs
signature verification; our job is strict configuration + validating every condition.

1. **SP-initiated only** (Fork 4): the SP issues an `AuthnRequest` with a stored `id`; the
   ACS validates `InResponseTo` == that id (replay / IdP-initiated-injection defense,
   vector 7). IdP-initiated is **deferred** (§13.3).
2. **Signature.** `wantAssertionsSigned=true`, `wantMessagesSigned` accepted; **unsigned
   assertions are rejected** (vector 5). python3-saml's processing defends against
   signature-wrapping/XSW (vector 4) — we additionally assert exactly one validated,
   signed assertion is consumed.
3. **Conditions (all fail-closed).** Validate Issuer == configured `idp_entity_id`,
   Audience == our SP entityID/audience (vector 2), Recipient + Destination == our ACS
   (vector 8), and `NotBefore`/`NotOnOrAfter` within skew (vector 6).
4. **Identity.** NameID is the `idp_subject`; the configured attribute (e.g.
   `groups`/`memberOf`) feeds D6. `tenant_id` = the tenant owning the matched `idp_config`
   (vector 2).

---

## 7. Decision D6 — Group→role mapping (per-tenant, fail-closed)

`idp_group_role_map` — `(tenant_id, idp_group, role)`, RLS-scoped. After a verified
assertion yields the subject's groups:

1. Resolve each group through the tenant's map to a role; take the **highest** mapped role.
2. **An IdP group with no mapping grants NO access** (never default-admin, R4). A subject
   whose groups map to **nothing** is **denied** — `operator_sso_denied` is emitted and the
   subject is **not** provisioned (vector 14).
3. On success, upsert the `admin_users` row + the `admin_role_assignments` row for the
   resolved role, then mint the operator-session (D2).

---

## 8. Decision D7 — Break-glass preserved + audited distinctly

The env `SENTINEL_ADMIN_TOKEN` path is **never removed** (R5) — it is the IdP-down recovery
and bootstrap path (the first operator, and config of the first IdP, happen via break-glass).
Every break-glass authentication emits a distinct **`admin_breakglass_used`** event, separate
from `operator_sso_login`, so break-glass use is always visible in the audit log. Break-glass
remains cross-tenant (its purpose); SSO is tenant-pinned (D2).

---

## 9. Decision D8 — Console integration (reuse the F-012 spine; rotate on login)

1. **Login UI** offers the configured SSO method(s) for the tenant **and** the break-glass
   token entry. SSO initiates via a frontend route that calls the Python admin SSO-initiate
   endpoint and redirects to the IdP.
2. **Callback** (frontend route) forwards the IdP response to the Python admin SSO-callback
   endpoint; on success the admin API returns the minted operator-session, which the
   frontend stores inside the **existing** `admin_session` cookie spine (httpOnly, secure,
   SameSite=strict) — **no parallel session** (R7). The cookie payload is extended
   backward-compatibly to distinguish a break-glass session from an SSO session (which
   carries the operator-session bearer).
3. **Session fixation (R7):** the session cookie is **rotated** (cleared + reissued) on every
   successful login (SSO and break-glass).
4. **BFF** branches: for an SSO session it presents the **operator-session** bearer to the
   admin API; for a break-glass session it presents the env token (as today). The admin
   token and the IdP secrets remain **server-side only**, never in the browser (R6).

---

## 10. Decision D9 — Event variants (4) + honest per-operator attribution (`actor_id`)

Four new variants, 4-site, all `action_taken='logged'` except the denial:

| event_type | emitted when | `tenant_id` | `agent_id` | `actor_id` | `action_taken` |
|---|---|---|---|---|---|
| `operator_sso_login` | SSO login succeeds | operator's tenant | `operator-sso` | the `admin_users.id` | `logged` |
| `operator_sso_denied` | assertion valid but no role / unknown subject | the tenant owning the `idp_config` (or `SYSTEM_TENANT_ID` if no tenant resolves pre-binding) | `operator-sso` | NULL | `blocked` |
| `admin_breakglass_used` | env-token break-glass authentication | `SYSTEM_TENANT_ID` (a system-scoped auth event — no single target tenant) | `admin-console` | NULL | `logged` |
| `idp_config_changed` | operator creates/updates/rotates a tenant IdP config | TARGET tenant | acting principal (`operator-sso` or `admin-console`) | the operator's `admin_users.id` (NULL for break-glass) | `logged` |

**The `actor_id` column (the vector-16 carrier).** The event schema has no per-operator
field and `agent_id` is a LOCKED component slug, so we add **one nullable content column**
`actor_id (uuid)` to `events_audit_log`. It holds the **internal `admin_users.id`** — an
opaque UUID, **not** the raw IdP subject/email (no PII, R6) — joinable (RLS-scoped) to the
operator identity. It is **folded into the hash-chain canonical form**: new rows include it;
all pre-F-014 rows and all non-operator events carry NULL and the canonicalizer treats
NULL consistently. This is the subtlest point in F-014's threat model (the analog of
ADR-0014's D8) and is called out for the STEP-10 auditor: the change to the canonical hash
input must be verified to (a) not break `validate_chain()` over a mixed old/new dataset and
(b) deterministically include/omit `actor_id`. `agent_id="operator-sso"` is a **new reserved
slug** (joining `admin-console`/`all-agents`/`rate-limiter`): it names the SSO subsystem as
the emitting principal while `actor_id` names the specific operator — honest attribution
that is **never** nil-UUID for an operator's tenant action and **never** the tenant's own
identity.

---

## 11. Decision D10 — Persistence (two reversible migrations) + 4-site consistency

- **`0014_sso_identity_schema`** (`down_revision="0013"`): create `admin_users`,
  `admin_roles`, `admin_role_assignments`, `idp_config`, `idp_group_role_map` with the
  standard tenant RLS policies (NOBYPASSRLS `sentinel_app`, `USING`/`WITH CHECK` on
  `app.current_tenant_id`); seed the two roles. `down()` drops them. Loss-free round-trip.
- **`0015_sso_event_variants`** (`down_revision="0014"`): widen `ck_eal_event_type` via the
  established DROP+ADD helper with the four new variants, and `ADD COLUMN actor_id uuid
  NULL` on `events_audit_log`. `down()` narrows the CHECK back to the F-012 set and drops
  `actor_id` (round-trip `…→0014→0015→0014→0015` verified at STEP 11).
- **4-site consistency** (the F-006 guard): the four variants land in lockstep across
  `events_audit_log.VALID_EVENT_TYPES`, `ACTION_TAKEN_BY_EVENT_TYPE`, the
  `ck_eal_event_type` CHECK (migration `0015`), and `contracts/events.schema.json`
  (api-architect). The migration **head-pin test** is bumped `0013→0015`.

---

## 12. Threat Model — 16 Vectors (CANONICAL; cite these numbers)

Each test **proves the attack fails** — asserting correct rejection **and** the correct
audit/response **and** no state corruption — not merely "raises". Planned test files:
`tests/admin/test_sso_tenant_isolation_threat_model.py` (1, 2, 3),
`tests/admin/test_saml_threat_model.py` (4, 5, 6, 7, 8),
`tests/admin/test_oidc_threat_model.py` (9, 10, 11, 12, 13),
`tests/admin/test_sso_authz_threat_model.py` (14, 15, 16).

| # | Vector | Control | Result |
|---|---|---|---|
| 1 | IdP A asserts an identity into tenant B | tenant-pin from operator-session + RLS (D2) | an assertion valid for A's IdP cannot authenticate or act on B |
| 2 | wrong audience/issuer accepted | aud/iss→tenant binding (D4/D5) | an assertion with wrong audience/issuer is rejected; tenant is the config owner, never the token |
| 3 | tenant reads/uses another tenant's IdP config | RLS on `idp_config` (D3) | cross-tenant IdP-config read returns zero rows / 404 |
| 4 | SAML signature-wrapping (XSW) | python3-saml processing + single-signed-assertion assert (D5) | a wrapped response is rejected |
| 5 | unsigned SAML assertion accepted | `wantAssertionsSigned`, unsigned rejected (D5) | unsigned assertion → rejected |
| 6 | expired / NotBefore SAML | NotBefore/NotOnOrAfter validation (D5) | out-of-window assertion → rejected |
| 7 | SAML replay / InResponseTo mismatch | SP-initiated `InResponseTo` binding, single-use (D5) | replayed/unsolicited assertion → rejected |
| 8 | wrong Recipient/Destination | Recipient+Destination == ACS (D5) | mismatch → rejected |
| 9 | OIDC state mismatch (CSRF) | `state` compare on callback (D4) | mismatched/absent state → rejected |
| 10 | OIDC nonce replay | single-use `nonce` (D4) | reused nonce → rejected |
| 11 | OIDC token not signed by IdP JWKS | JWKS signature verify (D4) | bad/forged signature → rejected |
| 12 | OIDC iss/aud/exp not validated | iss/aud/exp/iat checks (D4) | wrong iss/aud or expired → rejected |
| 13 | OIDC PKCE not enforced | S256 verifier required at code exchange (D4) | missing/bad verifier → rejected |
| 14 | unmapped group granted access | fail-closed group→role (D6) | a group with no mapping → denied, not provisioned, `operator_sso_denied` |
| 15 | break-glass broken or unaudited | env-token path kept + distinct event (D7) | env token works with no IdP configured **and** emits `admin_breakglass_used` |
| 16 | dishonest SSO attribution | `operator-sso` slug + `actor_id` + tenant (D9) | the audit names the real operator (`actor_id`) + tenant — never nil-UUID for the tenant action, never the tenant's own id |

### 12.1 Test isolation strategy
Cross-tenant proofs (1, 2, 3) commit real rows for two tenants across a second real RLS
connection and assert zero cross-tenant visibility (the ADR-0013/0014 §10.1 empirical
pattern). Assertion-validation proofs (4–13) use crafted/fixture assertions and a stubbed
IdP (JWKS / SAML metadata fixtures) — **no live IdP**; secrets/keys are runtime-assembled
test fixtures, never committed (the F-005 push-protection lesson). The `tests/admin/`
package's self-provisioning conftest (alembic upgrade head + SCRAM-provision `sentinel_app`,
skip-not-fail when no DB) covers the new tables.

---

## 13. Alternatives Considered, Honest Deferrals, Contracts, Rollback

### 13.1 Alternatives considered
- **Fork 1 (a) minimal single-role — NOT chosen.** Smaller surface, but Affu chose real
  RBAC (b) for a cleaner authz boundary (admin API authoritative) and a future-proof role
  model. Recorded for completeness.
- **Authz Model 1 (BFF env-token + advisory identity headers) — REJECTED with (b).** It
  leaves the env token as the sole authority and makes identity advisory; Model 2 makes the
  admin API verify the operator-session itself.
- **python-jose / pysaml2 — REJECTED.** authlib is maintained with full discovery/JWKS/PKCE;
  python-jose has had alg-confusion CVEs. python3-saml is the most-vetted SP toolkit with
  XSW defenses; pysaml2 is heavier. (R3: vetted, pinned.)
- **IdP-initiated SAML — DEFERRED.** Replay-harder (no `InResponseTo`); SP-initiated only.
- **Reuse the ES256 policy keypair for the operator-session — REJECTED.** Symmetric HMAC is
  correct for a token the admin API both mints and verifies; the ES256 keypair exists for an
  external signer.
- **A side table for operator attribution (no `actor_id` column) — REJECTED.** It would put
  honest attribution outside the tamper-evident chain; the nullable column keeps it inside.

### 13.2 Contract changes (api-architect, STEP 8)
- **`events.schema.json`:** add four closed variants (`operator_sso_login`,
  `operator_sso_denied`, `admin_breakglass_used`, `idp_config_changed`) to `oneOf`, each with
  the four stable IDs + `event_id`/`event_timestamp`/`request_id` + `action_taken` enum, plus
  the optional `actor_id` (uuid) field on the operator-attributed variants. No existing
  variant changes.
- **`ids.md`:** add the `operator-sso` reserved slug and document `actor_id` (the per-operator
  `admin_users.id` attribution carrier; never PII).
- **`openapi.yaml`:** add the SSO endpoints (per-tenant IdP-config CRUD under `adminAuth`;
  SSO initiate/callback for OIDC + SAML; admin-user/role read) and the `operatorSession`
  security posture. **No existing path changes.**
> Process note (mirrors ADR-0014 §13.1): `contracts/` edits are gated by the protect-paths
> hook authorizing only the `api-architect` identity. STEP 8 dispatches that agent; if its
> identity is not provisioned, the patch is recorded for verbatim re-apply. The protection is
> never weakened.

### 13.3 Honest scope / known limitations (v1)
**Admin surface ONLY** — no SSO on `/v1` (machine auth stays virtual API keys, R2) ·
**minimal RBAC** — two seeded roles (`tenant_admin`, `tenant_auditor`), not fine-grained
permissions · **one provider tested per protocol** (one OIDC IdP + one SAML IdP as proof,
not an exhaustive matrix) · **one IdP per tenant per protocol** (Fork 5; multi-IdP deferred) ·
**SP-initiated SAML only** (IdP-initiated deferred) · **SCIM provisioning deferred**
(just-in-time provisioning on first mapped login only) · **the IdP groups claim/attribute
name is fixed to `groups`** (per-IdP configurability deferred; an IdP that emits a
differently-named claim resolves to empty groups and is fail-closed denied) · **global
tenant-registry mutations remain break-glass-only** (no cross-tenant SSO path) ·
**break-glass is a single shared
env token** (no in-app lockout — the F-012a residual; brute force bounded by network) ·
IdP secrets + the operator-session + IdP-encryption keys are **deploy-injected**
(Vault/KMS), never in code/config/logs. "audit-ready", never "compliant".

### 13.4 Rollback
- **Whole feature:** revert `task/F-014-sso-native`. F-014 is purely additive (new
  `src/admin/sso/` + identity/IdP tables + SSO endpoints + the `require_admin` SSO branch +
  4 event variants + the `actor_id` column + 2 reversible migrations + frontend SSO login
  path). Reverting restores the exact pre-F-014 state; nothing in
  F-003/F-003b/F-005/F-008/F-011/F-012a is modified, and the env-token break-glass is
  unchanged.
- **Migrations:** `0015` drops `actor_id` + narrows the CHECK; `0014` drops the five tables.
  Both loss-free for pre-F-014 data. Verified at STEP 11.
- **Auth wiring:** removing the SSO branch from `require_admin` restores the exact F-012a
  env-token behavior; `/v1` is untouched throughout.
