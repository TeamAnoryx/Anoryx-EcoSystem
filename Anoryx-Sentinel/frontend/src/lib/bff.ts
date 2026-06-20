import { adminToken, sentinelApiUrl } from "@/lib/env";
import { AdminApiError, toFriendlyError } from "@/lib/errors";

/**
 * BFF proxy core (ADR-0015 D2). Pure-ish + testable: the route handler supplies
 * the resolved session state and request parts; this returns a status + body.
 *
 * Guarantees (tested in tests/unit/bff.test.ts):
 *  - Fail-closed: not authenticated → 401, NO upstream fetch (vector 3).
 *  - Path allow-listed to admin roots + traversal-guarded (no SSRF).
 *  - The admin bearer is injected here, server-side only (vectors 2, 5).
 *  - On upstream error only a mapped status + safe message is returned; the
 *    upstream body is discarded (vector 9). On success the upstream JSON passes
 *    through (the mint/rotate secret-once flow depends on this).
 */

export const ALLOWED_ROOTS = new Set(["tenants", "whoami"]);

export interface ProxyResult {
  status: number;
  body: unknown;
}

export interface ProxyInput {
  authenticated: boolean;
  segments: string[];
  search?: URLSearchParams;
  method: "GET" | "POST" | "PATCH";
  body?: string;
}

export async function handleAdminProxy(input: ProxyInput): Promise<ProxyResult> {
  const { authenticated, segments, search, method, body } = input;

  if (!authenticated) {
    return { status: 401, body: { error: "unauthenticated", reauth: true } };
  }
  if (segments.length === 0 || !ALLOWED_ROOTS.has(segments[0])) {
    return { status: 404, body: { error: "not_found" } };
  }
  if (segments.some((s) => s === ".." || s === "." || s.includes("/") || s.includes("\\"))) {
    return { status: 400, body: { error: "bad_request" } };
  }

  const subpath = segments.map(encodeURIComponent).join("/");
  const url = new URL(`${sentinelApiUrl()}/admin/${subpath}`);
  if (search) search.forEach((v, k) => url.searchParams.set(k, v));

  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${adminToken()}`,
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
