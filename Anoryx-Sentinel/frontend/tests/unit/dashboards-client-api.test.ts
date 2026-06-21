import { afterEach, describe, expect, it, vi } from "vitest";

import { clientApi } from "@/lib/client-api";

/**
 * Vector 2 (BFF-only data path): the dashboard feed polling helper must hit the
 * BFF (`/api/admin/*`) and never Sentinel directly, and must map errors safely.
 */

const realFetch = global.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("clientApi.get — BFF-only read path", () => {
  afterEach(() => {
    global.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it("fetches through the /api/admin BFF prefix, never Sentinel directly", async () => {
    const fetchMock = vi.fn((_url: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(
        jsonResponse({
          events: [],
          count: 0,
          next_cursor: null,
          chain_verified: true,
          chain_rows_checked: 0,
        }),
      ),
    );
    global.fetch = fetchMock as unknown as typeof fetch;

    await clientApi.get("tenants/t1/audit?after_sequence=0&limit=200");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "/api/admin/tenants/t1/audit?after_sequence=0&limit=200",
    );
  });

  it("maps a non-ok response to ClientApiError carrying the reauth flag", async () => {
    global.fetch = vi.fn(async () =>
      jsonResponse({ error: "unauthenticated", reauth: true }, 401),
    ) as unknown as typeof fetch;

    await expect(clientApi.get("tenants/t1/audit")).rejects.toMatchObject({
      status: 401,
      reauth: true,
    });
  });

  it("re-throws AbortError unchanged so the poller can ignore it", async () => {
    global.fetch = vi.fn(async () => {
      throw new DOMException("aborted", "AbortError");
    }) as unknown as typeof fetch;

    await expect(clientApi.get("tenants/t1/audit")).rejects.toMatchObject({ name: "AbortError" });
  });
});
