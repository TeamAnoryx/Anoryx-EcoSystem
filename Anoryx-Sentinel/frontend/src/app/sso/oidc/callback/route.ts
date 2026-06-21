import { NextResponse, type NextRequest } from "next/server";

import { sentinelApiUrl } from "@/lib/env";
import { setSsoSession } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * OIDC callback route (ADR-0017 D8 + D4). The IdP redirects the browser here
 * with ?code=...&state=... after the operator authenticates.
 *
 * This is the ONLY place the operator-session token from Python lands in the
 * Next.js process. It is immediately placed into the httpOnly cookie via
 * setSsoSession() — it is never written to the response body (R6).
 *
 * Flow:
 *  1. Extract `code` + `state` from query params.
 *  2. Server-to-server POST /admin/sso/oidc/callback {state, code} to Python.
 *     Python validates the OIDC assertion (D4: state, nonce, PKCE, JWKS, iss/aud/exp),
 *     resolves the group→role mapping (D6), and returns the minted operator-session.
 *  3. On 200: setSsoSession (rotates cookie, R7) → redirect to /.
 *  4. On 403 sso_no_role: redirect to /login?error=no_role.
 *  5. On any other failure: redirect to /login?error=sso_failed.
 *
 * IdP configuration note (for the README / operator):
 *   The IdP redirect_uri (OIDC) must be configured to this route's URL, e.g.:
 *   https://<console-host>/sso/oidc/callback
 *   Python's idp_config.sp_acs_url / OIDC redirect_uri must match this value.
 *
 * Note: this route accepts GET (browser redirect) which carries sec-fetch-site:
 * "none" or "cross-site" (it is the top-level navigation from the IdP). The
 * isCrossSite guard is intentionally NOT applied — this is a navigation endpoint,
 * not a form POST. Security relies on the `state` / PKCE validation server-side
 * in Python (D4 vectors 9, 13).
 */
export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const code = searchParams.get("code");
  const state = searchParams.get("state");

  if (!code || !state) {
    return NextResponse.redirect(new URL("/login?error=sso_failed", request.url));
  }

  let upstream: Response;
  try {
    upstream = await fetch(`${sentinelApiUrl()}/admin/sso/oidc/callback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ state, code }),
      cache: "no-store",
    });
  } catch {
    return NextResponse.redirect(new URL("/login?error=sso_failed", request.url));
  }

  if (upstream.status === 403) {
    let body: unknown;
    try {
      body = await upstream.json();
    } catch {
      body = null;
    }
    const isNoRole =
      body !== null &&
      typeof body === "object" &&
      (body as Record<string, unknown>).error === "sso_no_role";
    return NextResponse.redirect(
      new URL(isNoRole ? "/login?error=no_role" : "/login?error=sso_failed", request.url),
    );
  }

  if (!upstream.ok) {
    return NextResponse.redirect(new URL("/login?error=sso_failed", request.url));
  }

  let data: unknown;
  try {
    data = await upstream.json();
  } catch {
    return NextResponse.redirect(new URL("/login?error=sso_failed", request.url));
  }

  const d = data as Record<string, unknown>;
  const operatorToken = d?.operator_session_token;
  const role = d?.role;
  const tenantId = d?.tenant_id;

  if (
    typeof operatorToken !== "string" ||
    operatorToken.length === 0 ||
    typeof role !== "string" ||
    role.length === 0 ||
    typeof tenantId !== "string" ||
    tenantId.length === 0
  ) {
    return NextResponse.redirect(new URL("/login?error=sso_failed", request.url));
  }

  // Store the operator-session inside the httpOnly cookie ONLY (R6). Rotate cookie
  // to prevent fixation (R7).
  setSsoSession({ operatorToken, role, tenantId });

  return NextResponse.redirect(new URL("/", request.url));
}
