import { afterEach, describe, expect, it, vi } from "vitest";

// Mock the server-only env funnel so the proxy core is importable + deterministic.
vi.mock("@/lib/env", () => ({
  adminToken: () => "server-token",
  deltaApiUrl: () => "http://gw",
}));

import { handleAdminProxy } from "@/lib/bff";
import type { SessionPayload } from "@/lib/session-token";

const realFetch = global.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const SESSION: SessionPayload = {
  iat: 0,
  exp: Number.MAX_SAFE_INTEGER,
  principal: "delta-admin-console",
};

describe("BFF proxy core", () => {
  afterEach(() => {
    global.fetch = realFetch;
    vi.restoreAllMocks();
  });

  // ─── Unauthenticated ───────────────────────────────────────────────────────

  it("null session -> 401 and NO upstream call (fail-closed)", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: null, segments: ["allocations"], method: "GET" });
    expect(r.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // ─── Path guards ───────────────────────────────────────────────────────────

  it("rejects a non-allow-listed root -> 404, no upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: SESSION, segments: ["secrets"], method: "GET" });
    expect(r.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects path traversal (..) -> 400, no upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({
      session: SESSION,
      segments: ["allocations", "..", "history"],
      method: "GET",
    });
    expect(r.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an encoded-slash segment -> 400, no upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({
      session: SESSION,
      segments: ["allocations", "abc/def"],
      method: "GET",
    });
    expect(r.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a single-dot segment -> 400, no upstream call", async () => {
    const fetchMock = vi.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: SESSION, segments: ["allocations", "."], method: "GET" });
    expect(r.status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // ─── Bearer injection ──────────────────────────────────────────────────────

  it("injects the env bearer (server-token) and passes JSON through", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse([]));
    global.fetch = fetchMock as unknown as typeof fetch;
    const r = await handleAdminProxy({
      session: SESSION,
      segments: ["allocations"],
      search: new URLSearchParams({ tenant_id: "t1" }),
      method: "GET",
    });
    expect(r.status).toBe(200);
    expect(r.body).toEqual([]);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toBe("http://gw/v1/admin/allocations?tenant_id=t1");
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer server-token");
  });

  it("forwards POST body and Content-Type", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ allocation_id: "a1" }, 201));
    global.fetch = fetchMock as unknown as typeof fetch;
    await handleAdminProxy({
      session: SESSION,
      segments: ["allocations"],
      method: "POST",
      body: JSON.stringify({ tenant_id: "t1" }),
    });
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(init.body).toBe(JSON.stringify({ tenant_id: "t1" }));
  });

  // ─── Upstream error handling ───────────────────────────────────────────────

  it("upstream 5xx -> generic 500, no upstream detail leaked", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response("kaboom stack trace at line 42", { status: 503 })) as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: SESSION, segments: ["allocations"], method: "GET" });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toContain("kaboom");
  });

  it("upstream 401 -> re-auth signal", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(jsonResponse({ detail: "admin_unauthorized" }, 401)) as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: SESSION, segments: ["allocations"], method: "GET" });
    expect(r.status).toBe(401);
    expect(r.body).toMatchObject({ reauth: true });
  });

  it("upstream 409 (already decided) -> detail preserved for the UI", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(jsonResponse({ detail: "allocation_already_decided" }, 409)) as unknown as typeof fetch;
    const r = await handleAdminProxy({
      session: SESSION,
      segments: ["allocations", "a1", "decision"],
      method: "POST",
      body: "{}",
    });
    expect(r.status).toBe(409);
    expect(r.body).toMatchObject({ detail: "allocation_already_decided" });
  });

  it("network failure -> generic 500 (no detail leaked)", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED")) as unknown as typeof fetch;
    const r = await handleAdminProxy({ session: SESSION, segments: ["history"], method: "GET" });
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toContain("ECONNREFUSED");
  });

  it("204 -> status 204, null body", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 })) as unknown as typeof fetch;
    const r = await handleAdminProxy({
      session: SESSION,
      segments: ["allocations"],
      method: "GET",
    });
    expect(r.status).toBe(204);
    expect(r.body).toBeNull();
  });
});
