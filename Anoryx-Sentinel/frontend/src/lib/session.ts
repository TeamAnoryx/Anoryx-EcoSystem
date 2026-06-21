import "server-only";

import { cookies } from "next/headers";

import { cookieSecure, sessionSecret } from "@/lib/env";
import {
  ADMIN_PRINCIPAL,
  SESSION_TTL_SECONDS,
  issueBreakglassToken,
  issueSsoToken,
  verifySessionToken,
  type SessionPayload,
} from "@/lib/session-token";

/**
 * Cookie + env wrapper around the pure token crypto (ADR-0015 D1, ADR-0017 D8).
 *
 * httpOnly + Secure + SameSite=Strict. The cookie holds a HMAC-signed payload;
 * it never carries the env admin token or any IdP secret (R6).
 *
 * Session fixation guard (R7 / ADR-0017 D8 §3): every login rotates the cookie —
 * `clearSessionCookie()` is called BEFORE `setBreakglassSession()` or
 * `setSsoSession()`. The helpers below do this atomically.
 */

export const SESSION_COOKIE = "admin_session";
export { ADMIN_PRINCIPAL };

export function sessionCookieOptions(maxAgeSeconds: number = SESSION_TTL_SECONDS) {
  return {
    httpOnly: true as const,
    // Secure everywhere except local HTTP dev (where the browser would drop it).
    secure: cookieSecure(),
    sameSite: "strict" as const,
    path: "/",
    maxAge: maxAgeSeconds,
  };
}

/** Internal: clear the current session cookie (part of fixation-guard rotation). */
function _clearSession(): void {
  cookies().set(SESSION_COOKIE, "", sessionCookieOptions(0));
}

/**
 * Set a break-glass session. Rotates the cookie (R7): clear → issue new token.
 * Called by the break-glass login route after the env-token check + audit call.
 */
export function setBreakglassSession(): void {
  _clearSession();
  cookies().set(
    SESSION_COOKIE,
    issueBreakglassToken(sessionSecret()),
    sessionCookieOptions(),
  );
}

/**
 * Set an SSO session. Rotates the cookie (R7): clear → issue new token.
 * The `operatorToken` is the Python-issued operator-session Bearer — it is stored
 * inside the httpOnly cookie only; it never appears in a response body (R6).
 */
export function setSsoSession(opts: {
  operatorToken: string;
  role: string;
  tenantId: string;
}): void {
  _clearSession();
  cookies().set(
    SESSION_COOKIE,
    issueSsoToken(sessionSecret(), opts),
    sessionCookieOptions(),
  );
}

/**
 * @deprecated Use `setBreakglassSession()`. Kept for callers that predate F-014.
 * Delegates to `setBreakglassSession()` (which now also rotates — same behaviour).
 */
export function setSessionCookie(): void {
  setBreakglassSession();
}

export function clearSessionCookie(): void {
  _clearSession();
}

/** Read + verify the current request's session. `null` when unauthenticated. */
export function getSession(): SessionPayload | null {
  return verifySessionToken(cookies().get(SESSION_COOKIE)?.value, sessionSecret());
}
