import { NextResponse, type NextRequest } from "next/server";

import { sentinelApiUrl } from "@/lib/env";
import { setSsoSession } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * SAML Assertion Consumer Service (ACS) — HTTP-POST binding (ADR-0017 D5 + D8).
 *
 * The IdP auto-submits an HTML form directly to this URL with a SAMLResponse
 * (base64-encoded assertion). This is a cross-origin POST FROM the IdP — it is the
 * standard SAML POST binding. The `isCrossSite` guard is intentionally NOT applied
 * here because:
 *
 *   1. The POST originates from the IdP's domain (sec-fetch-site: "cross-site"),
 *      not from the console. Blocking it would break the SAML flow entirely.
 *   2. Security relies on assertion-level controls server-side in Python (D5):
 *      XML signature validation, InResponseTo (replay/IdP-initiated-injection),
 *      Issuer/Audience/Recipient/Destination checks, and NotBefore/NotOnOrAfter.
 *      These controls are robust; same-origin is not the right layer here.
 *
 * This is the documented exception to the cross-site guard pattern. The SAMLResponse
 * is forwarded opaquely to Python — we do not parse or validate the XML ourselves
 * (R3 — do not hand-roll XML signature validation).
 *
 * IdP configuration note (for the README / operator):
 *   The IdP ACS URL (SP service URL) must be configured to:
 *   https://<console-host>/sso/saml/acs
 *   Python's idp_config.sp_acs_url must match this value.
 *
 * Flow:
 *  1. Parse the form body for SAMLResponse (and RelayState if present).
 *  2. Forward to POST /admin/sso/saml/acs server-to-server.
 *  3. Same cookie-set + redirect handling as OIDC callback.
 */
export async function POST(request: NextRequest) {
  // Parse the IdP-submitted form body (application/x-www-form-urlencoded).
  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return NextResponse.redirect(new URL("/login?error=sso_failed", request.url));
  }

  const samlResponse = formData.get("SAMLResponse");
  const relayState = formData.get("RelayState");

  if (!samlResponse || typeof samlResponse !== "string") {
    return NextResponse.redirect(new URL("/login?error=sso_failed", request.url));
  }

  // Build payload for Python's /admin/sso/saml/acs.
  const acsPayload: Record<string, string> = { SAMLResponse: samlResponse };
  if (relayState && typeof relayState === "string") {
    acsPayload.RelayState = relayState;
  }

  let upstream: Response;
  try {
    upstream = await fetch(`${sentinelApiUrl()}/admin/sso/saml/acs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(acsPayload),
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
