# F-012 Admin Console Frontend — Security Audit

- **Feature:** F-012 (admin console frontend), ADR-0015.
- **Date:** 2026-06-21
- **Auditor:** security-auditor (independent red-team, Opus) + remediation by implementer.
- **Scope:** `Anoryx-Sentinel/frontend/` — auth/BFF spine, session, CSP/headers, screens.
- **Method:** manual threat-modeling of the new trust boundaries (browser↔BFF, BFF↔gateway,
  login, session cookie, CSP), Semgrep (`p/security-audit`, `p/secrets`, ERROR) on the
  security-critical files (0 findings), and empirical inspection of the built `.next/` output.

## Verdict

**PASS-with-conditions — 0 Critical, 0 High.** The load-bearing invariant (the admin token
never reaches the browser) holds empirically: the canary token is absent from `.next/static`
(vector 1), the bearer is injected only server-side (vectors 2, 5), and the session cookie
carries no token. The 2 Medium + 3 Low conditions raised by the auditor have all been
**remediated** in this branch (below). Two honest residuals are documented.

## Canonical vectors (ADR-0015 §11) — status

| # | Vector | Status |
|---|--------|--------|
| 1 | Token absent from client bundle | PASS — `check:token` greps `.next/static`, token absent (29 files) |
| 2 | Token absent from network | PASS — bearer attached only in `lib/admin-client.ts` + `lib/bff.ts` (server) |
| 3 | No session → login, no data, no upstream call | PASS — `(admin)/layout.tsx` guard + `bff.ts` 401-before-fetch (unit-tested) |
| 4 | Expired/forged session rejected | PASS — `session-token` unit tests |
| 5 | BFF injects bearer server-side only | PASS — `bff.test.ts` asserts `Authorization: Bearer` only in the proxy |
| 6 | Key secret shown once | PASS — `secret-reveal.tsx`; transient state, no re-fetch path |
| 7 | No cross-tenant data in client state | PASS — explicit `tenant_id` per call; `no-store`, no client cache |
| 8 | Strict CSP present | PASS (after M1 fix) — nonce + `strict-dynamic`, no script `unsafe-inline`; login now dynamic so the nonce applies |
| 9 | API error → friendly msg, no stack | PASS — `errors.ts` + `bff.ts` discard upstream body; `bff.test.ts` asserts no leak |

## Findings & remediation

| Sev | Finding | Remediation |
|-----|---------|-------------|
| MEDIUM | **CSP nonce generated but not applied to static `/login`/`_not-found`** — a per-request nonce can't bake into prerendered HTML, so the strict CSP wasn't enforced on those pages (and the login form would not hydrate under enforcement). | `/login` split into a server page (`force-dynamic`) + client `LoginForm`, so the middleware nonce is applied at render. `middleware.ts:src/app/login/page.tsx`. |
| MEDIUM | **No login brute-force throttle** (ADR D1 promised one). Unbounded online guessing oracle on the single operator secret. | Added in-memory per-IP fixed-window throttle (10 / 5 min → 429 + `Retry-After`). `lib/rate-limit.ts`, `api/login/route.ts`. Unit-tested. |
| LOW | **CSRF only via SameSite=Strict** on state-changing routes. | Added Sec-Fetch-Site cross-site rejection (403) on login + BFF mutations. `lib/request-guard.ts`. |
| LOW | **`unsafe-eval` CSP keyed off `NODE_ENV != production`** (fail-open for unknown env). | Flipped to `NODE_ENV === "development"` (fail-closed). `middleware.ts`. |
| LOW | **HSTS `preload` emitted from the app layer** — could affect sibling subdomains. | Dropped `preload`; HSTS preload/scope belongs at the TLS edge (Caddy). `middleware.ts`. |

## Honest residuals (accepted for v1)

- **`/_not-found` remains statically prerendered**, so its framework bootstrap scripts are not
  nonced. It renders no admin data and needs no interactivity; the residual is at most CSP
  console noise on a 404, not a data/again surface. (`/login` and all `(admin)` routes are
  dynamic and nonced.)
- **The login throttle is in-memory / per-process** and resets on restart. It raises the bar on
  online guessing for the single-operator v1; a distributed limit (or a Caddy edge limit) is the
  production hardening path. The primary defense remains a high-entropy `SENTINEL_ADMIN_TOKEN`.

## Post-remediation verification
`tsc` clean · eslint clean · 23/23 unit tests (incl. `bff.test.ts`, `rate-limit.test.ts`) ·
`next build` ✓ · `check:token` OK (token absent from client bundle).
