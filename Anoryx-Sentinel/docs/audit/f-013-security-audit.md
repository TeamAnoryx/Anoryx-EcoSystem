# F-013 Dashboards — Security Audit

- **Feature:** F-013 — Security / Compliance / Governance dashboards (frontend-only)
- **Branch:** `task/F-013-dashboards-native`
- **Date:** 2026-06-21
- **Auditor:** security-auditor (independent red-team), Opus
- **Scope:** `Anoryx-Sentinel/frontend/` dashboards + their data layer. No backend
  (`src/**` Python) or `contracts/**` change. Reuses the F-012 BFF/session/CSP spine.
- **Verdict: PASS** — 0 Critical, 0 High. 3 Low / informational (non-blocking).

## Threat vectors exercised

| # | Vector | Result |
|---|--------|--------|
| 1 | Session enforcement on dashboard routes | **HOLDS** — nested `dashboards/layout.tsx` is composed inside `(admin)/layout.tsx` `getSession()` redirect; all 3 pages `force-dynamic`; e2e confirms pre-auth redirect to `/login`, no data rendered. |
| 2 | BFF-only data path / token leak | **HOLDS** — client fetches go through `clientApi` → `/api/admin/*`; `admin-client.ts` + `env.ts` are `import "server-only"`; token injected only server-side (`admin-client.ts:55`, `bff.ts:54`); `check:token` clean on 30 client files; no client file references `process.env`/`adminToken`/`admin-client`/`dashboards-server`/`env`. |
| 3 | Cross-tenant leakage | **HOLDS** — no module-level dashboard data cache; `SecurityFeed key={tenant}` remounts on switch; `usePoll` clears state on `resetKey` change; server pages re-fetch per `?tenant=`. |
| 4 | XSS in feeds / breakdowns | **HOLDS** — zero `dangerouslySetInnerHTML` (enforced by source-scan unit test); every audit/tenant/model/gap field renders as inert React text; no user-controlled `href`/`src`. |
| 5 | CSP integrity | **INTACT** — strict nonce `script-src` with no `unsafe-inline` (dev-only `unsafe-eval`); only `style-src 'unsafe-inline'` relaxation (covers the allowed inline bar `width`); no script-src weakening. |
| 6 | Evidence-pack integrity | **HONEST** — pack download is deferred: a permanently disabled, labeled control; no download route, no byte mutation, no fake stream. Compliance reads only the JSON operator-evidence summary. |
| 7 | Input handling (SSRF / traversal) | **HOLDS** — `framework`/`window` allow-listed server-side; `tenant` `encodeURIComponent`-encoded into the path; gateway base pinned to URL origin; BFF allow-lists `segments[0] ∈ {tenants, whoami}` and rejects decoded `..`/`.`/`/`/`\`; CSRF defense-in-depth (`isCrossSite`) on non-GET. |

## Low / informational (non-blocking)

- **L1 — `dashboards-server.ts` forward-paging bound.** `fetchRecentAudit` caps at
  `PAGE_CAP=10 × PAGE_LIMIT=200 = 2000` events scanned per render, then keeps the
  tail; on a high-volume tenant the seed omits older events. Honesty/completeness
  limitation, documented in-file and in the feed footer. Not a security defect.
- **L2 — login rate limiter is per-process in-memory** (`rate-limit.ts`,
  pre-existing, **not F-013**). Out of scope; noted for production-hardening backlog.
- **N1 — `env.ts cookieSecure()`** reads `NODE_ENV` directly (allowed funnel
  exception); correct fail-closed (non-development always `Secure`).

## Evidence

- `tsc --noEmit` clean · `eslint` clean · `next build` ✓ (dashboards dynamic,
  bundles 0.7–3.2 kB) · 41 vitest unit tests pass · `check:token` — admin token
  absent from 30 client files.
- code-reviewer pass resolved before this audit: HIGH-1 (use-poll error →
  ClientApiError/toFriendlyError), MED-4 (Suspense around `useSearchParams`),
  MED-5 (honesty assertion); HIGH-2 (chain-status per-page) reviewed and rejected
  as a misread — `verify_chain()` is a global per-call result, not per-page;
  summing would double-count (clarifying comment added).

**No High/Critical to escalate. Cleared to proceed to the PR gate (human merges).**
