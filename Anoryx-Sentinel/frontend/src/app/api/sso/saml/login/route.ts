import { NextResponse, type NextRequest } from "next/server";

import { sentinelApiUrl } from "@/lib/env";
import { rateLimit } from "@/lib/rate-limit";
import { isCrossSite } from "@/lib/request-guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX_ATTEMPTS = 20;
const WINDOW_MS = 5 * 60 * 1000;

/**
 * SSO SAML initiation (ADR-0017 D8, unauthenticated — the operator has no session
 * yet). Calls POST /admin/sso/saml/login server-to-server and returns the IdP
 * redirect parameters so the client can redirect the browser to the IdP SSO URL.
 *
 * The response from Python may be a {redirect_url} (HTTP-Redirect binding) or POST
 * parameters for an HTML auto-submit form (HTTP-POST binding). We pass the payload
 * through; the client component handles both shapes.
 *
 * Security: same cross-site + rate-limit + anti-enumeration pattern as OIDC.
 */
export async function POST(request: NextRequest) {
  if (isCrossSite(request)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  const rl = rateLimit(`sso_saml_init:${ip}`, MAX_ATTEMPTS, WINDOW_MS);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: "too_many_attempts" },
      { status: 429, headers: { "Retry-After": String(Math.ceil(rl.retryAfterMs / 1000)) } },
    );
  }

  let tenantId: unknown;
  try {
    tenantId = (await request.json())?.tenant_id;
  } catch {
    return NextResponse.json({ error: "invalid_request" }, { status: 400 });
  }
  if (typeof tenantId !== "string" || tenantId.trim().length === 0) {
    return NextResponse.json({ error: "invalid_request" }, { status: 400 });
  }

  let upstream: Response;
  try {
    upstream = await fetch(`${sentinelApiUrl()}/admin/sso/saml/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_id: tenantId }),
      cache: "no-store",
    });
  } catch {
    return NextResponse.json({ error: "sso_unavailable" }, { status: 503 });
  }

  if (!upstream.ok) {
    return NextResponse.json({ error: "sso_unavailable" }, { status: 503 });
  }

  let data: unknown;
  try {
    data = await upstream.json();
  } catch {
    return NextResponse.json({ error: "sso_unavailable" }, { status: 503 });
  }

  // Pass through redirect_url or POST params — the client handles both shapes.
  return NextResponse.json(data);
}
