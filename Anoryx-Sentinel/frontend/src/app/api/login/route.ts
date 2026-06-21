import { createHash, timingSafeEqual } from "node:crypto";

import { NextResponse, type NextRequest } from "next/server";

import { adminToken, sentinelApiUrl } from "@/lib/env";
import { rateLimit } from "@/lib/rate-limit";
import { isCrossSite } from "@/lib/request-guard";
import { setBreakglassSession } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const MAX_ATTEMPTS = 10;
const WINDOW_MS = 5 * 60 * 1000;

/**
 * Operator break-glass login (ADR-0015 D1, Fork A; ADR-0017 D7+D8). Cross-site
 * rejected (L1), per-IP throttled (M2), then a fixed-length constant-time compare
 * of the submitted token to SENTINEL_ADMIN_TOKEN. Generic 401 on failure — no
 * detail leaked.
 *
 * On success:
 *  1. POST /admin/breakglass/login (server-to-server) to emit admin_breakglass_used.
 *     Design choice: audit failure → allow login and log server-side. Break-glass is
 *     the recovery path (IdP down, bootstrap); blocking it when the audit call fails
 *     would defeat its purpose. The audit event is best-effort; the secure outcome
 *     is NOT silently degraded.
 *  2. setBreakglassSession() rotates the cookie (fixation guard, R7).
 *
 * The env admin token is never stored client-side (R6 — unchanged).
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

  // Emit admin_breakglass_used audit event (ADR-0017 D7). Best-effort: if the
  // audit call fails we still allow login (break-glass is the recovery path — we
  // must not block it when the API is degraded). Failure is logged server-side.
  try {
    const auditRes = await fetch(`${sentinelApiUrl()}/admin/breakglass/login`, {
      method: "POST",
      headers: { Authorization: `Bearer ${adminToken()}` },
      cache: "no-store",
    });
    if (!auditRes.ok) {
      console.error(`[breakglass] audit endpoint returned ${auditRes.status} — login allowed`);
    }
  } catch (err) {
    console.error("[breakglass] audit endpoint unreachable — login allowed", err);
  }

  // Rotate session cookie (fixation guard, R7).
  setBreakglassSession();
  return NextResponse.json({ ok: true });
}
