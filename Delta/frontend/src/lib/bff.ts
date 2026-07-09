import { adminToken, deltaApiUrl } from "@/lib/env";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import type { SessionPayload } from "@/lib/session-token";

/**
 * BFF proxy core (mirrors Anoryx-Sentinel/frontend/src/lib/bff.ts, ADR-0015 D2).
 * Pure-ish + testable: the route handler supplies the resolved session state and
 * request parts; this returns a status + body.
 *
 * Guarantees (tested in tests/unit/bff.test.ts):
 *  - Fail-closed: not authenticated -> 401, NO upstream fetch.
 *  - Path allow-listed to admin roots + traversal-guarded (no SSRF).
 *  - Bearer injected here, server-side only: Authorization: Bearer
 *    <DELTA_ADMIN_TOKEN> (env). The token is NEVER accepted from the request
 *    and NEVER echoed back into a proxied response body.
 *  - On upstream error only a mapped status + safe message is returned; the
 *    upstream body is discarded (except the `detail` field, which is preserved
 *    so the UI can distinguish e.g. an already-decided 409). On success the
 *    upstream JSON passes through.
 */

export const ALLOWED_ROOTS = new Set([
  "allocations",
  "history",
  "dashboards",
  "chargeback",
  "crm",
  "erp",
  "pm",
  "capacity",
  "rbac",
]);

export interface ProxyResult {
  status: number;
  body: unknown;
}

export interface ProxyInput {
  /** Null means unauthenticated (fail-closed). */
  session: SessionPayload | null;
  segments: string[];
  search?: URLSearchParams;
  method: "GET" | "POST";
  body?: string;
}

export async function handleAdminProxy(input: ProxyInput): Promise<ProxyResult> {
  const { session, segments, search, method, body } = input;

  if (session === null) {
    return { status: 401, body: { error: "unauthenticated", reauth: true } };
  }
  if (segments.length === 0 || !ALLOWED_ROOTS.has(segments[0])) {
    return { status: 404, body: { error: "not_found" } };
  }
  if (segments.some((s) => s === ".." || s === "." || s.includes("/") || s.includes("\\"))) {
    return { status: 400, body: { error: "bad_request" } };
  }

  const subpath = segments.map(encodeURIComponent).join("/");
  const url = new URL(`${deltaApiUrl()}/v1/admin/${subpath}`);
  if (search) search.forEach((v, k) => url.searchParams.set(k, v));

  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method,
      headers: {
        // The token is injected here, server-side, and nowhere else.
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
    const upstreamBody = await upstream.json().catch(() => null);
    const detail =
      upstreamBody && typeof upstreamBody === "object" && "detail" in upstreamBody
        ? String((upstreamBody as { detail: unknown }).detail)
        : undefined;
    const f = toFriendlyError(new AdminApiError(upstream.status, "upstream", detail));
    return { status: f.status, body: { error: f.message, detail, reauth: f.reauth } };
  }

  if (upstream.status === 204) return { status: 204, body: null };
  const payload = await upstream.json().catch(() => null);
  return { status: upstream.status, body: payload };
}
