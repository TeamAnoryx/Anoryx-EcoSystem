import { afterEach, describe, expect, it, vi } from "vitest";

// Mock the server-only env funnel so the client is importable + deterministic.
vi.mock("@/lib/env", () => ({
  adminToken: () => "server-token",
  deltaApiUrl: () => "http://api",
}));

import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";

const realFetch = global.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("admin-client — adminFetch", () => {
  afterEach(() => {
    global.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it("attaches the bearer token and hits the expected URL + query", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse([]));
    global.fetch = fetchMock as unknown as typeof fetch;

    await adminApi.listAllocations("tenant-1", "requested");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toBe("http://api/v1/admin/allocations?tenant_id=tenant-1&status=requested");
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer server-token");
  });

  it("omits the status query param when not provided", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse([]));
    global.fetch = fetchMock as unknown as typeof fetch;

    await adminApi.listAllocations("tenant-1");

    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toBe("http://api/v1/admin/allocations?tenant_id=tenant-1");
  });

  it("createAllocation POSTs a JSON body with Content-Type", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ allocation_id: "a1" }, 201));
    global.fetch = fetchMock as unknown as typeof fetch;

    const body = {
      tenant_id: "t1",
      total_minor_units: 10_000,
      currency: "USD",
      period: "monthly" as const,
      targets: [],
      requested_by: "operator-1",
    };
    await adminApi.createAllocation(body);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(String(url)).toBe("http://api/v1/admin/allocations");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(init.body).toBe(JSON.stringify(body));
  });

  it("throws AdminApiError with status + detail on a non-2xx response (409 already-decided)", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(jsonResponse({ detail: "allocation_already_decided" }, 409)) as unknown as typeof fetch;

    await expect(
      adminApi.decideAllocation("a1", { tenant_id: "t1", action: "approve", actor: "op" }),
    ).rejects.toMatchObject({ status: 409, detail: "allocation_already_decided" });
  });

  it("throws AdminApiError with the 422 reconciliation detail verbatim", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(
        jsonResponse({ detail: "targets sum to 900 but total_minor_units is 1000" }, 422),
      ) as unknown as typeof fetch;

    let caught: unknown;
    try {
      await adminApi.createAllocation({
        tenant_id: "t1",
        total_minor_units: 1000,
        currency: "USD",
        period: "monthly",
        targets: [],
        requested_by: "op",
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AdminApiError);
    expect((caught as AdminApiError).detail).toBe("targets sum to 900 but total_minor_units is 1000");
  });

  it("network failure -> AdminApiError(502), no raw error leaked", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("ECONNREFUSED")) as unknown as typeof fetch;

    await expect(adminApi.listHistory("t1")).rejects.toMatchObject({ status: 502 });
  });

  it("204 response resolves to undefined", async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 })) as unknown as typeof fetch;

    await expect(
      adminApi.decideAllocation("a1", { tenant_id: "t1", action: "reject", actor: "op" }),
    ).resolves.toBeUndefined();
  });
});
