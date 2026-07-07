import "server-only";

/**
 * Server-only environment access (mirrors Anoryx-Sentinel/frontend/src/lib/env.ts,
 * F-012/ADR-0015 D1/D2, adapted for Delta's D-007 admin console).
 *
 * This is the SINGLE place env is read. Every value here is server-only and is
 * read lazily at request time (never at module top-level) so `next build` does
 * not require secrets to be present. None of these may ever be exposed to the
 * client: there is no `NEXT_PUBLIC_` variant of any of them. The eslint
 * `no-restricted-properties` rule forbids `process.env` everywhere except this
 * file, funnelling all access through here.
 */

function required(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === "") {
    // Fail-closed: a missing secret must never silently degrade to an open state.
    throw new Error(`Missing required server environment variable: ${name}`);
  }
  return value;
}

/**
 * Origin of the Delta allocation-admin API exposing /v1/admin/*
 * (server-to-server). We take the URL ORIGIN only — a stray path component in
 * DELTA_API_URL must not shift the admin paths (mirrors the Sentinel
 * code-review fix). Throws on a malformed URL.
 */
export function deltaApiUrl(): string {
  const raw = required("DELTA_API_URL");
  try {
    return new URL(raw).origin;
  } catch {
    throw new Error("DELTA_API_URL is not a valid URL (expected e.g. http://host:8010)");
  }
}

/** The break-glass operator credential. Injected server-side into /v1/admin/* calls only. */
export function adminToken(): string {
  return required("DELTA_ADMIN_TOKEN");
}

/** HMAC key for signing the session cookie. Distinct from the admin token. */
export function sessionSecret(): string {
  return required("SESSION_SECRET");
}

/**
 * Whether the session cookie should carry the `Secure` flag. Always true except
 * in local `development`, where Next serves plain HTTP and a Secure cookie would
 * be silently dropped (-> redirect loop). Production/preview stay Secure.
 */
export function cookieSecure(): boolean {
  return process.env.NODE_ENV !== "development";
}
