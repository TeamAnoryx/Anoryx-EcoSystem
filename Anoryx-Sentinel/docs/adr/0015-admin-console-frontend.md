# ADR-0015 — Admin Console Frontend (F-012)

- **Status:** Proposed
- **Date:** 2026-06-20
- **Deciders:** (frontend owner / implementer), api-architect (no contract change needed —
  consumes the existing `openapi.yaml` `/admin/*` surface), security-auditor (frontend
  red-team gate — the admin token is the highest-value secret in the product), platform-infra
  (deferred deploy wiring: root-compose service + Helm), Affu (solo founder & product owner —
  resolved the STEP-0 forks during planning: **Fork 1 auth/proxy = (A) token-entry → signed
  httpOnly session cookie**, **Fork 2 placement = `Anoryx-Sentinel/frontend/`**, **Fork 3
  deploy = separate Node container (Dockerfile + documented compose/Caddy now; Helm/root-compose
  deferred)**, **Fork 4 data-fetching = server-components-first + route handlers**; approves
  this ADR at the STEP-1 gate).
- **Supersedes / amends:** Builds **on top of** and **does not modify** ADR-0014 (F-012a admin
  API — this is its frontend; the console **consumes** `/admin/*` and never changes auth,
  schemas, or the RLS/audit model). **No `contracts/` change** (the `/admin/*` paths +
  `adminAuth` scheme already exist in `openapi.yaml`). Relates to ADR-0012 (F-010 deploy — the
  console deploys as an **additive** sidecar container; the gateway's slim image is untouched).
  Anticipates F-013 (dashboards — three nav slots stubbed here) and F-014 (SSO — explicitly
  deferred). Governed by `contracts/openapi.yaml`; **the contract wins over this ADR on any
  conflict.**
- **Feature:** F-012 — the **operator web console**: a Next.js 14 app that authenticates an
  operator, holds the admin credential **server-side only**, and proxies every `/admin/*` call
  through a Backend-for-Frontend (BFF) so the browser never sees `SENTINEL_ADMIN_TOKEN`. It is
  the **UI shell** F-013's dashboards plug into. This ADR covers the **base console + shell
  only** — not the F-013 dashboards.

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)
- **Admin API (ADR-0014, `src/admin/`):** `/admin/*` routes guarded by `require_admin` —
  `Authorization: Bearer <token>` compared constant-time to `SENTINEL_ADMIN_TOKEN`,
  **fail-closed** (unset/mismatch → 401, no tenant fallback). Pure bearer-per-request; the API
  has **no session concept** of its own. Endpoints: tenant lifecycle, key mint/list/rotate/revoke
  (secret returned **once**), keyset-paginated audit read (with `chain_verified` /
  `chain_rows_checked`), config view/adjust (F-007 classifier / F-009 audit-mode + RPM), policy
  status read, compliance-evidence (F-011). Smoke: `GET /admin/whoami`.
- **Contract:** `contracts/openapi.yaml` **already declares** every `/admin/*` path and the
  `adminAuth` security scheme (`http bearer`). The frontend conforms to it — **no contract edit**.
- **Deploy (ADR-0012, `deploy/`):** Docker Compose + Helm; **Caddy reverse-proxy already in
  the tree** (compose `tls` profile); secrets are env/file-injected; the gateway image is
  `python:3.12-slim` with **no Node**.
- **Source layout (`Anoryx-Sentinel/CLAUDE.md`):** designates `frontend/ — Next.js
  admin/compliance console`; the `frontend` builder agent is scoped to that path.
- **Env:** Node v24.13.1 / npm 11.8.0 present (Next 14 needs ≥18.17 — satisfied).

### 1.2 Decision (one paragraph)
We add a Next.js 14 (App Router) + TypeScript + Tailwind console under
**`Anoryx-Sentinel/frontend/`** (**D3**). The operator authenticates by entering the admin
token once into a login form; a Next.js **server route** constant-time-compares it to
`SENTINEL_ADMIN_TOKEN` (read from **server env**) and, on match, issues a **signed,
httpOnly + Secure + SameSite=Strict, short-TTL session cookie** carrying no token (**D1**,
Fork A). Every `/admin/*` request is proxied through a **BFF** — server components and route
handlers attach `Authorization: Bearer ${SENTINEL_ADMIN_TOKEN}` **server-side**; the browser
holds only the opaque session cookie and never sees the raw token (**D2**, R1/R2). Auth is
**fail-closed**: a server-side route-group guard verifies the session and `redirect('/login')`
before any admin data renders (**D2**, R3). Data fetching is **server-components-first** with
route handlers for mutations (**D5**, Fork 4) — admin data is fetched server-side, keeping the
client surface token-free and avoiding pre-auth data flash. The console ships the base screens
(tenants, keys with **secret-once** UX, policies, config, audit with chain-status, a read-only
RBAC view) plus a **nav/layout shell with three stubbed F-013 dashboard routes** (**D6**) so
F-013 drops in without restructuring. A strict **CSP** + security headers and a no-
`dangerouslySetInnerHTML` rule defend against XSS (**D7**, R6). Types are hand-written to mirror
`openapi.yaml`; no untyped fetch leaks into components (**D8**). The console deploys as a
**separate `node:20-slim` container** (**D4**, Fork 3) — Dockerfile + a documented compose
service/Caddy route now, Helm + root-compose wiring **deferred** to platform-infra. A **new,
additive** `frontend-ci.yml` lane runs lint/typecheck/build/tests without touching the Python
CI (**D9**, R8).

### 1.3 What changes vs. what is frozen
| Frozen (MUST NOT change) | Adds (F-012) |
|---|---|
| `src/admin/*`, `require_admin`, admin auth model (ADR-0014) | A frontend that **consumes** it; zero backend change |
| `contracts/openapi.yaml` `/admin/*` paths + `adminAuth` | **Untouched** — the console conforms to it |
| Tenant isolation / RLS / audit / hash chain | Read-only consumer via the API; never touched directly |
| Gateway container image (slim, ADR-0012) | A **separate** Node container; gateway image untouched |
| `.github/workflows/sentinel-ci.yml` (Python lane) | A **separate** `frontend-ci.yml`; Python lane untouched |
| `deploy/` root-compose + Helm | Console Dockerfile + **documented** compose/Caddy now; live wiring deferred |

---

## 2. Decision D1 — Operator auth = token-entry → signed httpOnly session cookie (Fork A)
The operator enters the admin token once into a login form. `POST /api/login` (a server route)
compares it to `SENTINEL_ADMIN_TOKEN` (server env) with a **constant-time** compare
(`crypto.timingSafeEqual` over equal-length buffers; unequal lengths short-circuit to fail).
On match it sets a **signed** session cookie (HMAC-SHA256 over a separate `SESSION_SECRET`),
payload `{iat, exp, principal:"admin-console"}` — **no token inside** — flags
**httpOnly + Secure + SameSite=Strict**, short TTL (~30 min). On mismatch: a generic 401, no
detail leak, with a basic per-IP attempt throttle (hardening). `POST /api/logout` clears the
cookie. Cookie verification rejects a missing/expired/forged cookie (vectors 3, 4).

**Why (A) over (B)/(C):** (A) mirrors Sentinel's own env-secret model (ADR-0014 D1,
`SENTINEL_KEY_SECRET`, `POLICY_SIGNING_*`) and meets R1 **cleanly** — the raw token lives in
**no** cookie, bundle, or network call. (B) iron-session's sealed-cookie variant that stores
the token (encrypted) in the browser cookie is a gray area vs R1's "token never in cookies";
its flag-only variant is just (A) with an extra dependency. (C) reverse-proxy/oauth2-proxy auth
is the cleanest F-014 SSO on-ramp but is heavy ops for a single operator and couples the
console to a deploy topology. (B)/(C) remain open future upgrades.

**What (A) forecloses (honest):** single-operator only (no per-operator identity — matches
ADR-0014's single `admin-console` principal); the console env holds a second copy of the token
alongside the gateway; rotating the token needs a console restart. Deferred, not denied.

## 3. Decision D2 — BFF for all `/admin/*`; fail-closed (R1/R2/R3)
No browser code ever calls Sentinel `/admin/*` directly. Two server-side paths, both inject the
bearer server-side:
1. **Server components** (reads) call `lib/admin-client.ts` directly (already server-side).
2. **Route handler `api/admin/[...path]`** (client-initiated mutations: mint/rotate/revoke,
   config PATCH) verifies the session **first** — absent/invalid ⇒ 401 with **no upstream call**
   (vector 3) — then forwards method/body/query to `${SENTINEL_API_URL}/admin/<path>` with the
   injected bearer (vector 5), maps errors via `lib/errors.ts` (vector 9), and never echoes the
   token.

**Fail-closed render:** the `(admin)` route-group `layout.tsx` is a server component that
verifies the session and `redirect('/login')` **before** rendering any admin page — no admin
data, no flash, no "default tenant" fallback (R3).

## 4. Decision D3 — Placement = `Anoryx-Sentinel/frontend/` (Fork 2)
Matches the documented source layout and the `frontend` agent's path; the existing CI path
filter `Anoryx-Sentinel/**` already covers it; root stays config-only (monorepo rule). The
dispatch's `admin-console/` wording is superseded by the repo's own layout (surfaced to and
confirmed by Affu).

## 5. Decision D4 — Deploy = separate Node container (Fork 3)
`frontend/Dockerfile`: `node:20-slim`, multi-stage (deps → `next build` → `next start`),
non-root, no secrets baked (R4). Runtime env injected at deploy: `SENTINEL_API_URL`
(e.g. `http://sentinel-app:8000`), `SENTINEL_ADMIN_TOKEN`, `SESSION_SECRET`. A compose service
block + Caddy route are **documented** (below); **live root-compose + Helm wiring is deferred**
to a platform-infra follow-up (cross-area; keeps F-012 scoped and the gateway slim image
untouched). Static-export was rejected — the BFF requires a server runtime to inject the token.

Documented compose service (for the platform-infra follow-up):
```yaml
admin-console:
  build: ./frontend
  environment:
    SENTINEL_API_URL: http://sentinel-app:8000
    SENTINEL_ADMIN_TOKEN_FILE: /run/secrets/sentinel_admin_token
    SESSION_SECRET_FILE: /run/secrets/admin_console_session_secret
  depends_on: [sentinel-app]
  # Caddy: route the console hostname/path -> reverse_proxy admin-console:3000
```

## 6. Decision D5 — Data fetching = server-components-first + route handlers (Fork 4)
Reads render in server components (token injected server-side; fail-closed by default; no
pre-auth flash). Mutations go through route handlers / server actions. Client interactivity is
minimal (key-mint/rotate secret-once modal, audit keyset cursor); optional client polling only
where it adds value. This maximizes the R1/R3 posture: admin data is never fetched from the
browser, and every screen is gated server-side.

## 7. Decision D6 — F-013 slot design
Top nav: **Tenants · Keys · Policies · Config · Audit · RBAC · Dashboards[Security ·
Compliance · Governance]**. The three dashboard routes exist as placeholder pages ("coming in
F-013"). Nav, layout, and auth are structured so F-013 fills the stub pages without modifying
nav/layout/auth — the explicit contract with the next task.

## 8. Decision D7 — XSS / headers (R6)
`middleware.ts` sets a strict **Content-Security-Policy** (`default-src 'self'`; scripts via
nonce, no `unsafe-inline`), plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, and HSTS. **No `dangerouslySetInnerHTML`** on any API-sourced
data — tenant names, policy names, audit content render as text only.

## 9. Decision D8 — Typed client (no contract edit)
`lib/types.ts` hand-mirrors the `openapi.yaml` components / `src/admin/schemas.py` models
(TenantResponse, TenantListResponse, KeyResponse, KeyMintResponse, KeyListResponse,
AuditEventResponse, AuditPageResponse, ConfigResponse, ConfigUpdateRequest, PolicyResponse,
…). A centralized typed client is the only fetch path; no untyped fetch in components.
(`openapi-typescript` codegen is a noted future option; hand-written types are kept for
determinism and zero codegen dependency.)

## 10. Decision D9 — Additive CI lane (R8)
New `.github/workflows/frontend-ci.yml`, trigger path filter `Anoryx-Sentinel/frontend/**`,
Node 20: `npm ci` → eslint → `tsc --noEmit` → `next build` → `vitest run` → **token-absence
build grep** (vector 1). Separate file + separate path filter ⇒ the Python lane
(`sentinel-ci.yml`) is **untouched** and the two lanes never share fixtures/ordering (the
F-009/F-011 CI anti-patterns are structurally avoided). Playwright vectors run locally;
browser-free token checks run in CI. If `.github/` writes are hook-blocked for the frontend
identity, the workflow is recorded for platform-infra to apply (the hook is never weakened).

---

## 11. Threat Model — 9 frontend vectors (CANONICAL; cite these numbers)
Each test **proves the attack fails**, not merely "renders". Test files:
`tests/e2e/*.spec.ts` (Playwright) + `tests/unit/*.test.ts` (vitest).

| # | Vector | Control | Result |
|---|---|---|---|
| 1 | Admin token in the built client bundle | token is server-env only; never `NEXT_PUBLIC_` (D1/D2) | grep of `.next/` client chunks after build finds **no** token value |
| 2 | Admin token on the wire (browser↔server) | BFF injects bearer server-side only (D2) | browser→server calls carry only the session cookie; the raw token never crosses |
| 3 | No session reaches admin data | server route-group guard; fail-closed (D2/R3) | protected routes `redirect('/login')`, render zero admin data, make no upstream call |
| 4 | Expired/forged session cookie accepted | signed cookie + exp check (D1) | tampered/expired cookie → re-login, no data |
| 5 | BFF bypass / token attached client-side | bearer attached only in server route (D2) | a crafted client request cannot obtain the token; injection happens server-side |
| 6 | Key secret re-readable after mint | secret-once modal; API has no re-fetch (D1 of ADR-0014) | secret shown once with copy + warning; no client re-fetch path exists |
| 7 | Cross-tenant data in client state | tenant_id explicit per call; server-first (D5/R4) | viewing tenant A never loads/caches/renders tenant B |
| 8 | XSS via API content / missing CSP | strict CSP + text-only render (D7/R6) | CSP header blocks inline script; no `dangerouslySetInnerHTML` on API data |
| 9 | API error leaks a stack to the UI | centralized error mapping (D2) | 5xx → operator-friendly message; no raw stack/trace in the DOM |

(9 vectors ≥ the dispatch's 9-vector requirement; vectors 1–2 are the load-bearing token-
absence proofs and are verified empirically before any screen is built.)

---

## 12. Alternatives Considered & Honest Deferrals
- **Fork 1 (B) sealed-cookie token / (C) reverse-proxy auth — DEFERRED (Affu chose A).** (B2)
  conflicts with R1 (encrypted token still in a cookie); (C) is the F-014 SSO on-ramp but heavy
  ops for one operator. Clean future upgrades.
- **Same-container deploy — REJECTED (Affu chose separate).** Adding Node to the slim Python
  image bloats it and mixes runtimes (anti-pattern); separate container scales/ships independently.
- **Static export — REJECTED.** The BFF needs a server runtime to keep the token server-side.
- **Client + react-query everywhere — REJECTED (Affu chose server-first).** Server-first keeps
  the client surface token-free and fail-closed by default.
- **OUT OF SCOPE (v1):** the three F-013 dashboards (slots only), SSO/SAML (F-014), multi-admin
  / per-operator attribution, real-time WebSocket security feed (F-013), live root-compose/Helm
  deploy wiring (platform-infra follow-up).

## 13. Consequences
### 13.1 Positive
- The operator credential never reaches the browser: token in server env, BFF-injected,
  fail-closed render. R1/R2/R3 hold by construction and are verified empirically (vectors 1–5).
- Conforms to an existing contract — zero backend/contract change, no new API surface to secure.
- F-013 plugs into a stable shell; SSO (F-014) has a clean upgrade path (Fork C / oauth2-proxy).
- CI and deploy are additive — the Python lane and the gateway image are untouched.

### 13.2 Honest scope / limitations (v1)
Single-operator (no multi-admin, no per-operator audit attribution — the API attributes all
admin actions to `admin-console`); token rotation needs a console restart; the console env
holds a second copy of the admin token; deploy is **deploy-ready** (Dockerfile + documented
compose/Caddy) but live root-compose/Helm wiring is deferred. UI language stays honest
("audit-ready", not "compliant"; "risk reduction", not "blocks all attacks").

### 13.3 Rollback
F-012 is **purely additive**: a new `frontend/` dir + a new `frontend-ci.yml`. Reverting
`task/F-012-admin-frontend-native` removes both and restores the exact prior state; nothing in
`src/`, `contracts/`, `deploy/` root-compose, or `sentinel-ci.yml` is modified.
