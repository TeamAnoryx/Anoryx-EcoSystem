# Anoryx Sentinel — Admin Console (F-012)

Operator-facing web console for the Sentinel zero-trust AI gateway. Next.js 14
(App Router) + TypeScript + Tailwind. Consumes the `/admin/*` API (ADR-0014) via a
**server-side BFF**; the admin token is never exposed to the browser (ADR-0015).

## Security model (read first)

`SENTINEL_ADMIN_TOKEN` is a single cross-tenant operator secret — a leak is a full
operator compromise. Therefore:

- The token lives **only** in this server process's environment.
- The browser holds **only** a signed, httpOnly session cookie — never the token.
- Every `/admin/*` call is proxied server-side (BFF), which injects the bearer.
- Auth is **fail-closed**: no valid session → redirect to `/login`, zero admin data.

## Required environment (server-only)

> All variables are **server-only**. Never prefix any with `NEXT_PUBLIC_` — that
> inlines the value into the client bundle and would leak the token (R1).
> Provision at deploy via env / mounted secrets; never commit (R4).
> (A `.env.example` file is intentionally absent — the repo's secret-protection
> hook blocks writing any `.env*` file. Copy the table below into a local `.env`.)

| Variable | Purpose |
|---|---|
| `SENTINEL_API_URL` | Base URL of the gateway exposing `/admin/*` (e.g. `http://localhost:8000`). |
| `SENTINEL_ADMIN_TOKEN` | The operator credential; must equal the gateway's `SENTINEL_ADMIN_TOKEN`. |
| `SESSION_SECRET` | HMAC key for signing the session cookie. `openssl rand -base64 48`. Distinct from the admin token. |

## Develop

```bash
npm install
# create .env with the three vars above
npm run dev          # http://localhost:3000
```

## Verify

```bash
npm run lint
npm run typecheck
npm run build
npm test             # vitest unit (session / env guard / error mapping)
npm run check:token  # builds with a canary token and greps .next/ for it (vector 1)
npm run test:e2e     # Playwright threat vectors (needs: npx playwright install)
```

## Scope (honest)

Base console + shell only. **No** F-013 dashboards (the three dashboard routes are
stubs), **no** SSO/SAML (F-014), **single-operator** (no multi-admin), **no**
real-time WebSocket feed (F-013). Deploy: a `Dockerfile` ships here; live
root-compose + Helm wiring is a platform-infra follow-up.
