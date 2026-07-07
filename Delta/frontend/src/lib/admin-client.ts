import "server-only";

import { adminToken, deltaApiUrl } from "@/lib/env";
import { AdminApiError } from "@/lib/errors";
import type {
  AllocationCreateRequest,
  AllocationStatus,
  AllocationView,
  ApprovalDecisionRequest,
  ChangeHistoryEntryView,
} from "@/lib/types";

/**
 * Server-only typed client for Delta's /v1/admin/* surface (D-007). Mirrors
 * Anoryx-Sentinel/frontend/src/lib/admin-client.ts.
 *
 * This module is the ONLY place the admin bearer is attached. It is marked
 * `server-only`, so importing it from a client component is a build error — the
 * token can never reach the browser. Server components and Server Actions call
 * through here; the catch-all BFF route (src/lib/bff.ts) also injects the
 * bearer independently for client-initiated calls.
 */

interface AdminFetchOptions {
  method?: "GET" | "POST";
  body?: unknown;
  query?: Record<string, string | number | undefined>;
}

function buildUrl(path: string, query?: AdminFetchOptions["query"]): string {
  const url = new URL(`${deltaApiUrl()}/v1/admin${path}`);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

export async function adminFetch<T>(path: string, opts: AdminFetchOptions = {}): Promise<T> {
  const { method = "GET", body, query } = opts;
  let res: Response;
  try {
    res = await fetch(buildUrl(path, query), {
      method,
      headers: {
        // The token is injected here, server-side, and nowhere else.
        Authorization: `Bearer ${adminToken()}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      cache: "no-store",
    });
  } catch {
    // Network/DNS failure reaching the Delta admin API — never leak details.
    throw new AdminApiError(502, "delta_api_unreachable");
  }

  if (!res.ok) {
    // Capture the `detail` field so callers can distinguish specific outcomes
    // (e.g. 409 "allocation_already_decided", 422 reconciliation errors) from a
    // generic error, without ever leaking raw upstream internals beyond it.
    const payload = await res.json().catch(() => null);
    const detail =
      payload && typeof payload === "object" && "detail" in payload
        ? String((payload as { detail: unknown }).detail)
        : undefined;
    throw new AdminApiError(res.status, `admin_api_error_${res.status}`, detail);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const adminApi = {
  listAllocations: (tenantId: string, status?: AllocationStatus) =>
    adminFetch<AllocationView[]>("/allocations", {
      query: { tenant_id: tenantId, status },
    }),

  getAllocation: (tenantId: string, allocationId: string) =>
    adminFetch<AllocationView>(`/allocations/${encodeURIComponent(allocationId)}`, {
      query: { tenant_id: tenantId },
    }),

  createAllocation: (body: AllocationCreateRequest) =>
    adminFetch<AllocationView>("/allocations", { method: "POST", body }),

  decideAllocation: (allocationId: string, body: ApprovalDecisionRequest) =>
    adminFetch<AllocationView>(
      `/allocations/${encodeURIComponent(allocationId)}/decision`,
      { method: "POST", body },
    ),

  listHistory: (tenantId: string, entityType?: string, entityId?: string) =>
    adminFetch<ChangeHistoryEntryView[]>("/history", {
      query: { tenant_id: tenantId, entity_type: entityType, entity_id: entityId },
    }),
};

export type AdminApi = typeof adminApi;
