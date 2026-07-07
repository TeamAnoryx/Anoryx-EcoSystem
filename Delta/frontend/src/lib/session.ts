import "server-only";

import { cookies } from "next/headers";

import { SESSION_COOKIE } from "@/lib/cookie-name";
import { cookieSecure, sessionSecret } from "@/lib/env";
import {
  ADMIN_PRINCIPAL,
  SESSION_TTL_SECONDS,
  issueSessionToken,
  verifySessionToken,
  type SessionPayload,
} from "@/lib/session-token";

/**
 * Cookie + env wrapper around the pure token crypto (mirrors
 * Anoryx-Sentinel/frontend/src/lib/session.ts).
 *
 * httpOnly + Secure + SameSite=Strict. The cookie holds an HMAC-signed payload;
 * it never carries the env admin token.
 *
 * Session-fixation guard: every login rotates the cookie — `clearSessionCookie()`
 * runs BEFORE `setSession()` mints the new one. `setSession()` does this
 * atomically.
 */

export { SESSION_COOKIE };
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
 * Mint a new admin session. Rotates the cookie (session-fixation guard):
 * clear -> issue new token. Called by the login route after the constant-time
 * token compare succeeds.
 */
export function setSession(): void {
  _clearSession();
  cookies().set(SESSION_COOKIE, issueSessionToken(sessionSecret()), sessionCookieOptions());
}

export function clearSessionCookie(): void {
  _clearSession();
}

/** Read + verify the current request's session. `null` when unauthenticated. */
export function getSession(): SessionPayload | null {
  return verifySessionToken(cookies().get(SESSION_COOKIE)?.value, sessionSecret());
}
