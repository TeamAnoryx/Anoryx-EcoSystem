import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Pure session-token crypto (ADR-0015 D1, extended by ADR-0017 D8). No env, no
 * next/headers, no `server-only` — the signing secret is injected by the caller —
 * so this is directly unit-testable. The cookie/env wiring lives in `session.ts`.
 *
 * Token = `base64url(payload).base64url(HMAC-SHA256(payload, secret))`.
 *
 * Discriminated payload (backward-compatible — see migration note in verifySessionToken):
 *   break-glass: { iat, exp, kind:"breakglass", principal:"admin-console" }
 *   sso:         { iat, exp, kind:"sso", operatorToken:<Python bearer>,
 *                  role:<"tenant_admin"|"tenant_auditor">, tenantId:<uuid> }
 *
 * The `operatorToken` is the Python-issued short-lived Bearer that the admin API
 * independently verifies (D2 tenant-pin + role enforcement). It lives ONLY inside
 * this httpOnly cookie — never in any response body, never NEXT_PUBLIC_ (R6).
 * The HMAC here provides cookie integrity; the Python HMAC-SHA256 inside the token
 * provides admin API authorization. Two distinct secrets, two distinct trust claims.
 */

export const ADMIN_PRINCIPAL = "admin-console";
export const SSO_KIND = "sso" as const;
export const BREAKGLASS_KIND = "breakglass" as const;
export const SESSION_TTL_SECONDS = 30 * 60; // 30 minutes

// ─── Discriminated session types ─────────────────────────────────────────────

export interface BreakglassPayload {
  iat: number;
  exp: number;
  kind: "breakglass";
  principal: "admin-console";
}

export interface SsoPayload {
  iat: number;
  exp: number;
  kind: "sso";
  /** The Python-issued operator-session Bearer. Tenant-pinned + role-scoped (D2). */
  operatorToken: string;
  role: string;
  tenantId: string;
}

/**
 * Legacy break-glass payload from F-012 (before F-014 added `kind`). Accepted on
 * read only — never issued. Migration: if `principal` == ADMIN_PRINCIPAL and no
 * `kind`, treat as break-glass (backward-compat).
 */
export interface LegacyPayload {
  iat: number;
  exp: number;
  principal: string;
}

export type SessionPayload = BreakglassPayload | SsoPayload;

// ─── Internal HMAC ───────────────────────────────────────────────────────────

function sign(payloadB64: string, secret: string): string {
  return createHmac("sha256", secret).update(payloadB64).digest("base64url");
}

// ─── Issue ───────────────────────────────────────────────────────────────────

export function issueBreakglassToken(
  secret: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): string {
  const payload: BreakglassPayload = {
    iat: nowSeconds,
    exp: nowSeconds + SESSION_TTL_SECONDS,
    kind: BREAKGLASS_KIND,
    principal: ADMIN_PRINCIPAL,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${payloadB64}.${sign(payloadB64, secret)}`;
}

export function issueSsoToken(
  secret: string,
  opts: { operatorToken: string; role: string; tenantId: string },
  nowSeconds: number = Math.floor(Date.now() / 1000),
): string {
  const payload: SsoPayload = {
    iat: nowSeconds,
    exp: nowSeconds + SESSION_TTL_SECONDS,
    kind: SSO_KIND,
    operatorToken: opts.operatorToken,
    role: opts.role,
    tenantId: opts.tenantId,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${payloadB64}.${sign(payloadB64, secret)}`;
}

/**
 * @deprecated Use `issueBreakglassToken` for new break-glass sessions. This shim
 * keeps the old call-site in the login route working during the transition.
 */
export function issueSessionToken(
  secret: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): string {
  return issueBreakglassToken(secret, nowSeconds);
}

// ─── Verify ──────────────────────────────────────────────────────────────────

/**
 * Verify a token. Returns the discriminated payload when:
 *   1. HMAC-SHA256 signature is valid (constant-time compare)
 *   2. Token is unexpired
 *   3. Payload is a recognized kind (breakglass or sso) OR legacy format (→ breakglass)
 * Returns `null` on any failure (fail-closed).
 *
 * Legacy migration: an F-012 token has `{iat, exp, principal:"admin-console"}` and no
 * `kind`. We promote it to BreakglassPayload so existing sessions survive a rolling
 * deploy; callers treat it identically.
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

  // Discriminate on `kind` field
  if (raw.kind === BREAKGLASS_KIND) {
    if (raw.principal !== ADMIN_PRINCIPAL) return null;
    return raw as unknown as BreakglassPayload;
  }

  if (raw.kind === SSO_KIND) {
    if (
      typeof raw.operatorToken !== "string" ||
      raw.operatorToken.length === 0 ||
      typeof raw.role !== "string" ||
      raw.role.length === 0 ||
      typeof raw.tenantId !== "string" ||
      raw.tenantId.length === 0
    ) {
      return null;
    }
    return raw as unknown as SsoPayload;
  }

  // Legacy F-012 break-glass cookie: no `kind`, has `principal`.
  if (!raw.kind && raw.principal === ADMIN_PRINCIPAL) {
    return {
      iat: raw.iat as number,
      exp: raw.exp as number,
      kind: BREAKGLASS_KIND,
      principal: ADMIN_PRINCIPAL,
    };
  }

  return null;
}
