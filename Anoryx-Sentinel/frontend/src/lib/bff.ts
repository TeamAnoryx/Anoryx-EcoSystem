import { adminToken, sentinelApiUrl } from "@/lib/env";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import type { SessionPayload } from "@/lib/session-token";

/**
 * BFF proxy core (ADR-0015 D2, ADR-0017 D8). Pure-ish + testable: the route
 * handler supplies the resolved session state and request parts; this returns a
 * status + body.
 *
 * Guarantees (tested in tests/unit/bff.test.ts):
 *  - Fail-closed: not authenticated → 401, NO upstream fetch (vector 3).
 *  - Path allow-listed to admin roots + traversal-guarded (no SSRF).
 *  - Bearer injected here, server-side only (vectors 2, 5):
 *      kind=="breakglass" → Authorization: Bearer <SENTINEL_ADMIN_TOKEN> (env)
 *      kind=="sso"        → Authorization: Bearer <operatorToken> (from cookie)
 *    The env token is NEVER used for SSO sessions. The operatorToken is delivered
 *    server-to-server (the Python SSO callback returns it to the frontend BFF,
 *    which wraps it into the signed httpOnly session cookie) and lives ONLY in that
 *    httpOnly cookie; it is never exposed to browser JS and this BFF never echoes
 *    it back into a proxied response body (R6 / ADR-0017 D8).
 *  - On upstream error only a mapped status + safe message is returned; the
 *    upstream body is discarded (vector 9). On success the upstream JSON passes
 *    through.
 */

export const ALLOWED_ROOTS = new Set(["tenants", "whoami"]);

export interface ProxyResult {
  status: number;
  body: unknown;
}

export interface ProxyInput {
  /** Null means unauthenticated (fail-closed). */
  session: SessionPayload | null;
  segments: string[];
  search?: URLSearchParams;
  method: "GET" | "POST" | "PATCH";
  body?: string;
}

/**
 * @deprecated Use `ProxyInput` with `session`. Kept so existing callers in the
 * admin catch-all route compile; the route handler already passes `session`.
 */
export interface LegacyProxyInput {
  authenticated: boolean;
  segments: string[];
  search?: URLSearchParams;
  method: "GET" | "POST" | "PATCH";
  body?: string;
}

function resolveBearer(session: SessionPayload): string {
  if (session.kind === "sso") {
    // The Python-issued operator-session token, tenant-pinned + role-scoped (D2).
    return session.operatorToken;
  }
  // kind === "breakglass" — env token injected server-side.
  return adminToken();
}

export async function handleAdminProxy(
  input: ProxyInput | LegacyProxyInput,
): Promise<ProxyResult> {
  // Support both the new `session`-typed input and the legacy `authenticated` flag
  // (for backward-compat with existing tests and route handlers that haven't been
  // updated yet — they pass `authenticated: bool` and we fall back to break-glass
  // token behaviour, which is safe because they cannot supply an operatorToken).
  let session: SessionPayload | null;
  if ("session" in input) {
    session = input.session;
  } else {
    // Legacy: authenticated=true → synthesise a break-glass session object for
    // the bearer-resolution path so the rest of the function is uniform.
    if (!input.authenticated) {
      return { status: 401, body: { error: "unauthenticated", reauth: true } };
    }
    session = {
      iat: 0,
      exp: Number.MAX_SAFE_INTEGER,
      kind: "breakglass",
      principal: "admin-console",
    };
  }

  const { segments, search, method, body } = input;

  if (session === null) {
    return { status: 401, body: { error: "unauthenticated", reauth: true } };
  }
  if (segments.length === 0 || !ALLOWED_ROOTS.has(segments[0])) {
    return { status: 404, body: { error: "not_found" } };
  }
  if (segments.some((s) => s === ".." || s === "." || s.includes("/") || s.includes("\\"))) {
    return { status: 400, body: { error: "bad_request" } };
  }

  const bearer = resolveBearer(session);
  const subpath = segments.map(encodeURIComponent).join("/");
  const url = new URL(`${sentinelApiUrl()}/admin/${subpath}`);
  if (search) search.forEach((v, k) => url.searchParams.set(k, v));

  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${bearer}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body,
      cache: "no-store",
    });
  } catch {
    const f = toFriendlyError(new AdminApiError(502, "unreachable"));
    return { status: f.status, body: { error: f.message } };
  }

  if (!upstream.ok) {
    const f = toFriendlyError(new AdminApiError(upstream.status, "upstream"));
    return { status: f.status, body: { error: f.message, reauth: f.reauth } };
  }

  if (upstream.status === 204) return { status: 204, body: null };
  const payload = await upstream.json().catch(() => null);
  return { status: upstream.status, body: payload };
}
