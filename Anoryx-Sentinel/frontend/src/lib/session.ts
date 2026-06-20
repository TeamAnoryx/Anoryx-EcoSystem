import "server-only";

import { cookies } from "next/headers";

import { cookieSecure, sessionSecret } from "@/lib/env";
import {
  ADMIN_PRINCIPAL,
  SESSION_TTL_SECONDS,
  issueSessionToken,
  verifySessionToken,
  type SessionPayload,
} from "@/lib/session-token";

/**
 * Cookie + env wrapper around the pure token crypto (ADR-0015 D1). httpOnly +
 * Secure + SameSite=Strict; the cookie holds only a signed marker, never the
 * admin token (R1). Fail-closed reads (vectors 3, 4).
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

export function setSessionCookie(): void {
  cookies().set(SESSION_COOKIE, issueSessionToken(sessionSecret()), sessionCookieOptions());
}

export function clearSessionCookie(): void {
  cookies().set(SESSION_COOKIE, "", sessionCookieOptions(0));
}

/** Read + verify the current request's session. `null` when unauthenticated. */
export function getSession(): SessionPayload | null {
  return verifySessionToken(cookies().get(SESSION_COOKIE)?.value, sessionSecret());
}
