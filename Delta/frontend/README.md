# Anoryx Delta — Budget Allocation Admin Console (D-007)

Operator-facing web console for Delta's budget-allocation admin API. Next.js 14
(App Router) + TypeScript + Tailwind. Consumes `/v1/admin/*` on
`delta.allocation_admin.app:create_app` via a **server-side BFF**; the admin
token is never exposed to the browser. Mirrors the reference implementation in
`Anoryx-Sentinel/frontend/` (Sentinel's admin console, F-012), adapted for
Delta's single break-glass token (no SSO).

## Security model (read first)

The browser holds **only** a signed HMAC-SHA256 httpOnly cookie
(`delta_admin_session`) — never a bearer token. Every server-side call that
reaches Delta's admin API attaches `Authorization: Bearer <DELTA_ADMIN_TOKEN>`
from the env, in exactly one of two places:

- `src/lib/admin-client.ts` (`adminFetch`) — used by server components and
  Server Actions, which already run server-side.
- `src/lib/bff.ts` (`handleAdminProxy`) — the documented BFF seam for any
  future client-fetch / non-page consumer, wired up at
  `src/app/api/admin/[...path]/route.ts`.

**Session-fixation guard:** every successful login rotates the session cookie
(clear -> reissue) via `setSession()` in `src/lib/session.ts`.

**Layered route guard:**
1. `src/middleware.ts` runs on the Edge runtime, which has no `node:crypto`.
   It only checks whether the session cookie is *present* and redirects to
   `/login` if not — a cheap, edge-safe UX redirect for the common
   never-logged-in / logged-out case. It is **not** the security boundary.
2. `src/app/(admin)/layout.tsx` is the authoritative, fail-closed gate: it
   calls `getSession()` (full HMAC verification, Node runtime) and redirects
   to `/login` if the session is missing or invalid — *before* any admin data
   is fetched or rendered.
3. `src/lib/bff.ts` independently fails closed (401, no upstream fetch) for
   any client-initiated call through the proxy route, regardless of what the
   middleware or layout did.

## Which mechanism does each mutation/read use?

Per this monorepo's BFF-only-frontend convention, `src/lib/bff.ts` +
`src/app/api/admin/[...path]/route.ts` are required scaffolding even though
the app's own pages don't route through them today:

| Path | Mechanism |
|---|---|
| `/allocations`, `/allocations/[id]`, `/history` (reads) | Server components calling `adminApi.*` directly (`src/lib/admin-client.ts`) — they already run server-side, so no extra network hop through the BFF proxy is needed. |
| Create allocation, Approve/Reject decision (writes) | Server Actions (`src/app/(admin)/allocations/actions.ts`, `"use server"`) calling `adminApi.*` directly, invoked from client components via a plain function call (not `<form action>`/`useFormState`) so the calling component can branch on a typed `{ok, status, detail, message}` result and render inline errors — including the 409 "already decided" case — without a generic toast. |
| `/api/admin/[...path]` (BFF proxy) | Built + unit-tested (`tests/unit/bff.test.ts`) as the documented seam for a future client-fetch consumer or SPA rewrite. Not currently called by any page in this app. |
| `/api/login`, `/api/logout` | Plain client `fetch` from `login-form.tsx` / `logout-button.tsx` — these routes exist specifically to bridge browser -> server for auth, which is their entire purpose. |

## Money handling (non-negotiable)

Every money field is an **integer minor units** (cents) value end-to-end. The
"New allocation" form's amount inputs are integer minor-units fields directly
— never a dollar input parsed into a float and sent to the API. A read-only,
purely-cosmetic dollar preview (`src/lib/money.ts` — `formatMinorUnits`) is
computed from the same integer for operator convenience; its output is never
parsed back into a request. This is a **client-side cost estimate** for
display only, not a source of truth.

## Required environment (server-only)

> All variables are **server-only**. Never prefix any with `NEXT_PUBLIC_`.
> (A `.env.example` file is intentionally absent — this repo's secret-
> protection hook blocks writing any `.env*` file. Copy the table below into a
> local `.env`.)

| Variable | Purpose |
|---|---|
| `DELTA_API_URL` | Origin of the Delta allocation-admin API (e.g. `http://localhost:8010`). Path components are stripped — only the origin is used. |
| `DELTA_ADMIN_TOKEN` | The single break-glass operator credential (`Authorization: Bearer <token>`). |
| `SESSION_SECRET` | HMAC key for signing the session cookie. `openssl rand -base64 48`. Distinct from `DELTA_ADMIN_TOKEN`. |

## Develop

```bash
npm install
# create .env with DELTA_API_URL, DELTA_ADMIN_TOKEN, SESSION_SECRET
npm run dev          # http://localhost:3000
```

## Verify

```bash
npm run lint
npm run typecheck
DELTA_API_URL=http://127.0.0.1:9 DELTA_ADMIN_TOKEN=__canary__ SESSION_SECRET=__x__ npm run build
npm test              # vitest unit (env / session-token / bff / admin-client)
npm run test:render   # vitest jsdom render lane (login form)
DELTA_ADMIN_TOKEN=__canary__ npm run check:token  # greps .next/static for the canary token
```

## Scope (honest — risk reduction, not a guarantee)

- Single shared break-glass token; no per-operator accounts or SSO in v1.
- No tenant directory UI — operators enter the tenant UUID directly on the
  Allocations and History pages. This is a known, stated limitation.
- No live Delta backend was available while building this console; the build
  and test commands above use canary/placeholder env values, mirroring how
  Sentinel's CI sets a canary env for its own frontend build step.
- The middleware-level redirect is a UX convenience only — see "Layered route
  guard" above for where the real fail-closed enforcement lives.
