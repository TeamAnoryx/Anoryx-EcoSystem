# Anoryx Sentinel — Admin Console (F-012 + F-014 SSO)

Operator-facing web console for the Sentinel zero-trust AI gateway. Next.js 14
(App Router) + TypeScript + Tailwind. Consumes the `/admin/*` API (ADR-0014,
ADR-0017) via a **server-side BFF**; the admin token and operator-session tokens
are never exposed to the browser (ADR-0015, R6).

## Security model (read first)

Two authentication paths share the same httpOnly session cookie spine (ADR-0015 D1,
ADR-0017 D8):

| Path | Session kind | Bearer injected by BFF |
|---|---|---|
| SSO (OIDC / SAML) | `kind:"sso"` — cookie carries the Python operator-session | `operator_session_token` from the cookie |
| Break-glass | `kind:"breakglass"` | `SENTINEL_ADMIN_TOKEN` from the env |

The browser holds **only** a signed HMAC-SHA256 httpOnly cookie — never any bearer
token. The BFF injects the right bearer server-side based on `session.kind`. Every
break-glass authentication emits `admin_breakglass_used` in the audit log.

**Session fixation guard (R7):** every login (SSO and break-glass) rotates the
session cookie (clear → reissue) before redirecting to the console.

## Required environment (server-only)

> All variables are **server-only**. Never prefix any with `NEXT_PUBLIC_` — that
> inlines the value into the client bundle (R6). Provision at deploy via env /
> mounted secrets; never commit (R4).
> (A `.env.example` file is intentionally absent — the repo's secret-protection
> hook blocks writing any `.env*` file. Copy the table below into a local `.env`.)

| Variable | Purpose |
|---|---|
| `SENTINEL_API_URL` | Base URL of the gateway exposing `/admin/*` (e.g. `http://localhost:8000`). |
| `SENTINEL_ADMIN_TOKEN` | Break-glass operator credential. Never used for SSO sessions. |
| `SESSION_SECRET` | HMAC key for signing the session cookie. `openssl rand -base64 48`. Distinct from all other secrets. |

**Python-side secrets** (deploy-injected server-side in the gateway — NOT needed
here; listed for completeness):

| Python secret | Purpose |
|---|---|
| `SENTINEL_ADMIN_SESSION_SECRET` | HMAC key for the Python-minted operator-session tokens (distinct from `SESSION_SECRET`). |
| `SENTINEL_IDP_SECRET_KEY` | AES-256-GCM key for IdP client_secret + SP private key encryption at rest. |

## IdP redirect / ACS configuration

The operator must configure the IdP (and the Python `idp_config` record) with the
following console-side URLs. Replace `<console-host>` with the deployed console
origin.

| Protocol | Type | URL |
|---|---|---|
| OIDC | Redirect URI | `https://<console-host>/sso/oidc/callback` |
| SAML | Assertion Consumer Service (ACS) | `https://<console-host>/sso/saml/acs` |

The Python `idp_config.sp_acs_url` field must equal the ACS URL above. The OIDC
`redirect_uri` used by Python must equal the OIDC redirect URI above.

**SAML note:** `/sso/saml/acs` accepts cross-origin POST (the IdP auto-submits an
HTML form to it — this is the standard HTTP-POST binding). The standard `isCrossSite`
guard is not applied to this route; security relies on Python's server-side assertion
validation (XML signature, InResponseTo, Issuer/Audience/Recipient, time window).

## Develop

```bash
npm install
# create .env with SENTINEL_API_URL, SENTINEL_ADMIN_TOKEN, SESSION_SECRET
npm run dev          # http://localhost:3000
```

## Verify

```bash
npm run lint
npm run typecheck
npm run build
npm test             # vitest unit (session / bff / sso-routes / env guard / errors)
npm run check:token  # greps .next/ for the canary token (vector 1)
npm run test:e2e     # Playwright threat vectors (needs: npx playwright install)
```

## SSO login flow (summary)

1. Operator enters their tenant identifier on the SSO tab and clicks "Sign in with SSO".
2. Console POSTs to `/api/sso/oidc/login` (server route) → Python returns `authorization_url`.
3. Browser is redirected to the IdP.
4. IdP redirects back to `/sso/oidc/callback?code=...&state=...`.
5. The callback route POSTs to Python `/admin/sso/oidc/callback`; Python validates the
   assertion (PKCE, state, nonce, JWKS, iss/aud, group→role) and returns an
   `operator_session_token`.
6. The route calls `setSsoSession({operatorToken, role, tenantId})` — the token is
   stored inside the httpOnly cookie, never in the response body.
7. Browser is redirected to `/` (the admin dashboard).

SAML flow is analogous: `/api/sso/saml/login` → IdP → `/sso/saml/acs` (POST).

## Scope (honest)

- SSO: OIDC + SAML SP-initiated (F-014). IdP-initiated SAML deferred.
- Single active IdP per tenant per protocol (v1). Multi-IdP deferred.
- Break-glass: single shared env token (no in-app operator lockout in v1).
- No SCIM provisioning (just-in-time on first mapped login only, Python-side).
- Dashboard panels: F-013 (security / compliance / governance stubs filled).
- No real-time WebSocket feed (F-013 polling).
