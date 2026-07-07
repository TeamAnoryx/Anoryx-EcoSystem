import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Pure session-token crypto (mirrors Anoryx-Sentinel/frontend/src/lib/session-token.ts).
 * No env, no next/headers, no `server-only` — the signing secret is injected by
 * the caller — so this is directly unit-testable. The cookie/env wiring lives in
 * `session.ts`.
 *
 * Delta has a single auth path (break-glass `DELTA_ADMIN_TOKEN`, no SSO), so the
 * payload is a single, non-discriminated shape — simpler than Sentinel's
 * breakglass/sso union.
 *
 * Token = `base64url(payload).base64url(HMAC-SHA256(payload, secret))`.
 */

export const ADMIN_PRINCIPAL = "delta-admin-console";
export const SESSION_TTL_SECONDS = 30 * 60; // 30 minutes

export interface SessionPayload {
  iat: number;
  exp: number;
  principal: "delta-admin-console";
}

function sign(payloadB64: string, secret: string): string {
  return createHmac("sha256", secret).update(payloadB64).digest("base64url");
}

export function issueSessionToken(
  secret: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): string {
  const payload: SessionPayload = {
    iat: nowSeconds,
    exp: nowSeconds + SESSION_TTL_SECONDS,
    principal: ADMIN_PRINCIPAL,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${payloadB64}.${sign(payloadB64, secret)}`;
}

/**
 * Verify a token. Returns the payload when:
 *   1. HMAC-SHA256 signature is valid (constant-time compare)
 *   2. Token is unexpired
 *   3. Payload shape + principal match
 * Returns `null` on any failure (fail-closed).
 */
export function verifySessionToken(
  token: string | undefined | null,
  secret: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): SessionPayload | null {
  if (!token) return null;
  const dot = token.indexOf(".");
  if (dot <= 0 || dot === token.length - 1) return null;

  const payloadB64 = token.slice(0, dot);
  const providedSig = token.slice(dot + 1);
  const expectedSig = sign(payloadB64, secret);

  const a = Buffer.from(providedSig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;

  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as Record<
      string,
      unknown
    >;
  } catch {
    return null;
  }

  if (typeof raw?.exp !== "number" || raw.exp <= nowSeconds) return null;
  if (typeof raw?.iat !== "number") return null;
  if (raw.principal !== ADMIN_PRINCIPAL) return null;

  return {
    iat: raw.iat as number,
    exp: raw.exp as number,
    principal: ADMIN_PRINCIPAL,
  };
}
