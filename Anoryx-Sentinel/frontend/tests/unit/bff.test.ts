import { afterEach, describe, expect, it, vi } from "vitest";

// Mock the server-only env funnel so the proxy core is importable + deterministic.
vi.mock("@/lib/env", () => ({
  adminToken: () => "server-token",
  sentinelApiUrl: () => "http://gw",
}));

import { handleAdminProxy } from "@/lib/bff";
import type { BreakglassPayload, SsoPayload } from "@/lib/session-token";

const realFetch = global.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const BREAKGLASS_SESSION: BreakglassPayload = {
  iat: 0,
  exp: Number.MAX_SAFE_INTEGER,
  kind: "breakglass",
  principal: "admin-console",
};

const SSO_SESSION: SsoPayload = {
  iat: 0,
  exp: Number.MAX_SAFE_INTEGER,
  kind: "sso",
  operatorToken: "operator-token-from-python",
  role: "tenant_admin",
  tenantId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
};

describe("BFF proxy core", () => {
  afterEach(() => {
    global.fetch = realFetch;
    vi.restoreAllMocks();
  });

  // ─── Unauthenticated ───────────────────────────────────────────────────────

  it("vector 3 — null session → 401 and NO upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: null, segments: ["tenants"], method: "GET" });
    expect(r.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("legacy authenticated:false → 401 and NO upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({ authenticated: false, segments: ["tenants"], method: "GET" });
    expect(r.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // ─── Path guards ───────────────────────────────────────────────────────────

  it("rejects a non-allow-listed root → 404, no upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: BREAKGLASS_SESSION, segments: ["secrets"], method: "GET" });
    expect(r.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects path traversal → 400, no upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({
      session: BREAKGLASS_SESSION,
      segments: ["tenants", "..", "whoami"],
      method: "GET",
    });
    expect(r.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // ─── Break-glass bearer ────────────────────────────────────────────────────

  it("vector 5 — break-glass: injects env bearer (server-token) and passes JSON through", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ count: 0, tenants: [] }));
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({
      session: BREAKGLASS_SESSION,
      segments: ["tenants"],
      search: new URLSearchParams({ limit: "10" }),
      method: "GET",
    });
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ count: 0, tenants: [] });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toBe("http://gw/admin/tenants?limit=10");
    // Break-glass → env token ("server-token"), NOT the operatorToken.
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer server-token");
  });

  it("legacy authenticated:true → env bearer injected (break-glass compat)", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    global.fetch = fetchMock as unknown as typeof fetch;
    await handleAdminProxy({ authenticated: true, segments: ["tenants"], method: "GET" });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer server-token");
  });

  // ─── SSO bearer ───────────────────────────────────────────────────────────

  it("SSO session: injects the operatorToken (NOT the env token)", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({
      session: SSO_SESSION,
      segments: ["tenants"],
      method: "GET",
    });
    expect(r.status).toBe(200);
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    // SSO → operatorToken, never the env admin token.
    expect((init.headers as Record<string, string>)["Authorization"]).toBe(
      "Bearer operator-token-from-python",
    );
    // Env token must NOT appear.
    expect((init.headers as Record<string, string>)["Authorization"]).not.toContain("server-token");
  });

  it("SSO session: operatorToken is NOT echoed in the response body", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ data: "some-result" }));
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({
      session: SSO_SESSION,
      segments: ["tenants"],
      method: "GET",
    });
    // The response body must never contain the operatorToken.
    expect(JSON.stringify(r.body)).not.toContain("operator-token-from-python");
  });

  // ─── Upstream error handling ───────────────────────────────────────────────

  it("vector 9 — upstream 5xx → generic 500, no upstream detail leaked", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response("kaboom stack trace at line 42", { status: 503 })) as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: BREAKGLASS_SESSION, segments: ["tenants"], method: "GET" });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toContain("kaboom");
  });

  it("upstream 401 → re-auth signal", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response("nope", { status: 401 })) as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: BREAKGLASS_SESSION, segments: ["tenants"], method: "GET" });
    expect(r.status).toBe(401);
    expect(r.body).toMatchObject({ reauth: true });
  });

  it("network failure → generic 500 (no detail leaked)", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED")) as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: BREAKGLASS_SESSION, segments: ["whoami"], method: "GET" });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toContain("ECONNREFUSED");
  });

  it("204 → status 204, null body", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 })) as unknown as typeof fetch;
    const r = await handleAdminProxy({
      session: BREAKGLASS_SESSION,
      segments: ["tenants", "abc", "deactivate"],
      method: "POST",
    });
    expect(r.status).toBe(204);
    expect(r.body).toBeNull();
  });
});
