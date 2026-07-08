import { createHash, timingSafeEqual } from "node:crypto";

import { NextResponse, type NextRequest } from "next/server";

import { adminToken } from "@/lib/env";
import { isCrossSite } from "@/lib/request-guard";
import { setSession } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Operator break-glass login (D-007, mirrors Anoryx-Sentinel/frontend's
 * src/app/api/login/route.ts). Cross-site rejected, then a fixed-length
 * constant-time compare of the submitted token to DELTA_ADMIN_TOKEN. Generic
 * 401 on failure — no detail leaked.
 *
 * The token itself is NEVER stored client-side — only the signed httpOnly
 * session cookie is, minted by `setSession()` (which also rotates the cookie:
 * session-fixation guard).
 */
export async function POST(request: NextRequest) {
  if (isCrossSite(request)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  let submitted: unknown;
  try {
    submitted = (await request.json())?.token;
  } catch {
    return NextResponse.json({ error: "invalid_request" }, { status: 400 });
  }
  if (typeof submitted !== "string" || submitted.length === 0) {
    return NextResponse.json({ error: "invalid_credentials" }, { status: 401 });
  }

  // Fixed-length SHA-256 digests under timingSafeEqual: neither content nor
  // length of the configured token is timing-observable. SHA-256 is
  // collision-resistant, so equal digests => equal tokens.
  const expected = createHash("sha256").update(adminToken()).digest();
  const got = createHash("sha256").update(submitted).digest();
  if (!timingSafeEqual(got, expected)) {
    return NextResponse.json({ error: "invalid_credentials" }, { status: 401 });
  }

  // Rotate session cookie (session-fixation guard).
  setSession();
  return NextResponse.json({ ok: true });
}
