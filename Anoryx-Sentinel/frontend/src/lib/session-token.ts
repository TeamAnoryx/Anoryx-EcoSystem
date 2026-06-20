import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Pure session-token crypto (ADR-0015 D1). No env, no next/headers, no
 * `server-only` — the signing secret is injected by the caller — so this is
 * directly unit-testable. The cookie/env wiring lives in `session.ts`.
 *
 * Token = `base64url(payload).base64url(HMAC-SHA256(payload, secret))`.
 * The payload carries `{iat, exp, principal}` and NO admin token (R1).
 */

export const ADMIN_PRINCIPAL = "admin-console";
export const SESSION_TTL_SECONDS = 30 * 60; // 30 minutes

export interface SessionPayload {
  iat: number;
  exp: number;
  principal: string;
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
 * Verify a token. Returns the payload only when the signature is valid (constant
 * time) AND the token is unexpired AND the principal matches; otherwise `null`
 * (fail-closed — vectors 3, 4).
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

  let payload: SessionPayload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as SessionPayload;
  } catch {
    return null;
  }
  if (typeof payload?.exp !== "number" || payload.exp <= nowSeconds) return null;
  if (payload.principal !== ADMIN_PRINCIPAL) return null;
  return payload;
}
