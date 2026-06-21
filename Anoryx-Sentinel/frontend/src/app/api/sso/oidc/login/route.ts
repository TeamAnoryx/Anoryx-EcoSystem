import { NextResponse, type NextRequest } from "next/server";

import { sentinelApiUrl } from "@/lib/env";
import { rateLimit } from "@/lib/rate-limit";
import { isCrossSite } from "@/lib/request-guard";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX_ATTEMPTS = 20;
const WINDOW_MS = 5 * 60 * 1000;

/**
 * SSO OIDC initiation (ADR-0017 D8, unauthenticated — the operator has no session
 * yet). Calls POST /admin/sso/oidc/login server-to-server and returns the
 * authorization_url so the client can redirect the browser to the IdP.
 *
 * Security:
 *  - Cross-site guard (state-changing POST from the console form only).
 *  - Per-IP rate-limited to bound enumeration.
 *  - Uniform error on any SSO failure (anti-enumeration — mirrors the Python
 *    uniform 404 for unknown tenant/protocol).
 *  - No IdP secrets ever reach this handler (they live Python-side, encrypted
 *    at rest per D3/R6).
 */
export async function POST(request: NextRequest) {
  if (isCrossSite(request)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  const rl = rateLimit(`sso_oidc_init:${ip}`, MAX_ATTEMPTS, WINDOW_MS);
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
    upstream = await fetch(`${sentinelApiUrl()}/admin/sso/oidc/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenant_id: tenantId }),
      cache: "no-store",
    });
  } catch {
    // Anti-enumeration: uniform error regardless of the failure cause.
    return NextResponse.json({ error: "sso_unavailable" }, { status: 503 });
  }

  if (!upstream.ok) {
    // Uniform error — do not leak whether the tenant/IdP config exists.
    return NextResponse.json({ error: "sso_unavailable" }, { status: 503 });
  }

  let data: unknown;
  try {
    data = await upstream.json();
  } catch {
    return NextResponse.json({ error: "sso_unavailable" }, { status: 503 });
  }

  const authUrl = (data as Record<string, unknown>)?.authorization_url;
  if (typeof authUrl !== "string" || authUrl.length === 0) {
    return NextResponse.json({ error: "sso_unavailable" }, { status: 503 });
  }

  return NextResponse.json({ authorization_url: authUrl });
}
