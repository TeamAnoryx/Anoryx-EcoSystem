import { createHash, timingSafeEqual } from "node:crypto";

import { NextResponse, type NextRequest } from "next/server";

import { adminToken } from "@/lib/env";
import { rateLimit } from "@/lib/rate-limit";
import { isCrossSite } from "@/lib/request-guard";
import { setSessionCookie } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX_ATTEMPTS = 10;
const WINDOW_MS = 5 * 60 * 1000;

/**
 * Operator login (ADR-0015 D1, Fork A). Cross-site rejected (L1), per-IP
 * throttled (M2), then a fixed-length constant-time compare of the submitted
 * token to SENTINEL_ADMIN_TOKEN. Generic 401 on failure — no detail leaked.
 */
export async function POST(request: NextRequest) {
  if (isCrossSite(request)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  const rl = rateLimit(`login:${ip}`, MAX_ATTEMPTS, WINDOW_MS);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: "too_many_attempts" },
      { status: 429, headers: { "Retry-After": String(Math.ceil(rl.retryAfterMs / 1000)) } },
    );
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

  // Fixed-length SHA-256 digests under timingSafeEqual: neither content nor length
  // of the configured token is timing-observable. SHA-256 is collision-resistant,
  // so equal digests ⇒ equal tokens.
  const expected = createHash("sha256").update(adminToken()).digest();
  const got = createHash("sha256").update(submitted).digest();
  if (!timingSafeEqual(got, expected)) {
    return NextResponse.json({ error: "invalid_credentials" }, { status: 401 });
  }

  setSessionCookie();
  return NextResponse.json({ ok: true });
}
