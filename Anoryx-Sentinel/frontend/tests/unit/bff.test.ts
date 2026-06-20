import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the server-only env funnel so the proxy core is importable + deterministic.
vi.mock("@/lib/env", () => ({
  adminToken: () => "server-token",
  sentinelApiUrl: () => "http://gw",
}));

import { handleAdminProxy } from "@/lib/bff";

const realFetch = global.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("BFF proxy core", () => {
  afterEach(() => {
    global.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it("vector 3 — unauthenticated → 401 and NO upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({ authenticated: false, segments: ["tenants"], method: "GET" });
    expect(r.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a non-allow-listed root → 404, no upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({ authenticated: true, segments: ["secrets"], method: "GET" });
    expect(r.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects path traversal → 400, no upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({
      authenticated: true,
      segments: ["tenants", "..", "whoami"],
      method: "GET",
    });
    expect(r.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("vector 5 — injects the bearer server-side and passes through JSON", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ count: 0, tenants: [] }));
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({
      authenticated: true,
      segments: ["tenants"],
      search: new URLSearchParams({ limit: "10" }),
      method: "GET",
    });
    expect(r.status).toBe(200);
    expect(r.body).toEqual({ count: 0, tenants: [] });
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe("http://gw/admin/tenants?limit=10");
    expect((init as RequestInit).headers).toMatchObject({ Authorization: "Bearer server-token" });
  });

  it("vector 9 — upstream 5xx → generic 500, no upstream detail leaked", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response("kaboom stack trace at line 42", { status: 503 })) as unknown as typeof fetch;
    const r = await handleAdminProxy({ authenticated: true, segments: ["tenants"], method: "GET" });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toContain("kaboom");
  });

  it("upstream 401 → re-auth signal", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response("nope", { status: 401 })) as unknown as typeof fetch;
    const r = await handleAdminProxy({ authenticated: true, segments: ["tenants"], method: "GET" });
    expect(r.status).toBe(401);
    expect(r.body).toMatchObject({ reauth: true });
  });

  it("network failure → generic 500 (no detail leaked)", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED")) as unknown as typeof fetch;
    const r = await handleAdminProxy({ authenticated: true, segments: ["whoami"], method: "GET" });
    // All 5xx (incl. the 502 we raise on a network error) collapse to a generic 500.
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toContain("ECONNREFUSED");
  });

  it("204 → status 204, null body", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 })) as unknown as typeof fetch;
    const r = await handleAdminProxy({
      authenticated: true,
      segments: ["tenants", "abc", "deactivate"],
      method: "POST",
    });
    expect(r.status).toBe(204);
    expect(r.body).toBeNull();
  });
});
