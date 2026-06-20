import "server-only";

import { adminToken, sentinelApiUrl } from "@/lib/env";
import { AdminApiError } from "@/lib/errors";
import type {
  AuditPageResponse,
  ConfigResponse,
  ConfigUpdateRequest,
  KeyListResponse,
  KeyMintRequest,
  KeyMintResponse,
  KeyResponse,
  PolicyListResponse,
  TenantCreateRequest,
  TenantListResponse,
  TenantResponse,
  WhoamiResponse,
} from "@/lib/types";

/**
 * Server-only typed client for the Sentinel /admin/* surface (ADR-0015 D2/D8).
 *
 * This module is the ONLY place the admin bearer is attached. It is marked
 * `server-only`, so importing it from a client component is a build error — the
 * token can never reach the browser. The catch-all BFF route and server
 * components both call through here.
 */

interface AdminFetchOptions {
  method?: "GET" | "POST" | "PATCH";
  body?: unknown;
  query?: Record<string, string | number | undefined>;
}

function buildUrl(path: string, query?: AdminFetchOptions["query"]): string {
  const url = new URL(`${sentinelApiUrl()}${path}`);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

async function adminFetch<T>(path: string, opts: AdminFetchOptions = {}): Promise<T> {
  const { method = "GET", body, query } = opts;
  let res: Response;
  try {
    res = await fetch(buildUrl(path, query), {
      method,
      headers: {
        // The token is injected here, server-side, and nowhere else (R1/R2).
        Authorization: `Bearer ${adminToken()}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      cache: "no-store",
    });
  } catch {
    // Network/DNS failure reaching the gateway — never leak details.
    throw new AdminApiError(502, "gateway_unreachable");
  }

  if (!res.ok) {
    // Map the status only; the upstream body is intentionally discarded (vector 9).
    throw new AdminApiError(res.status, `admin_api_error_${res.status}`);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ---- Tenants -------------------------------------------------------------- //
export const adminApi = {
  whoami: () => adminFetch<WhoamiResponse>("/admin/whoami"),

  listTenants: (limit = 100, offset = 0) =>
    adminFetch<TenantListResponse>("/admin/tenants", { query: { limit, offset } }),
  getTenant: (tenantId: string) =>
    adminFetch<TenantResponse>(`/admin/tenants/${encodeURIComponent(tenantId)}`),
  createTenant: (body: TenantCreateRequest) =>
    adminFetch<TenantResponse>("/admin/tenants", { method: "POST", body }),
  deactivateTenant: (tenantId: string) =>
    adminFetch<TenantResponse>(`/admin/tenants/${encodeURIComponent(tenantId)}/deactivate`, {
      method: "POST",
    }),

  // ---- Keys --------------------------------------------------------------- //
  listKeys: (tenantId: string) =>
    adminFetch<KeyListResponse>(`/admin/tenants/${encodeURIComponent(tenantId)}/keys`),
  mintKey: (tenantId: string, body: KeyMintRequest) =>
    adminFetch<KeyMintResponse>(`/admin/tenants/${encodeURIComponent(tenantId)}/keys`, {
      method: "POST",
      body,
    }),
  rotateKey: (tenantId: string, keyId: string) =>
    adminFetch<KeyMintResponse>(
      `/admin/tenants/${encodeURIComponent(tenantId)}/keys/${encodeURIComponent(keyId)}/rotate`,
      { method: "POST" },
    ),
  revokeKey: (tenantId: string, keyId: string) =>
    adminFetch<KeyResponse>(
      `/admin/tenants/${encodeURIComponent(tenantId)}/keys/${encodeURIComponent(keyId)}/revoke`,
      { method: "POST" },
    ),

  // ---- Audit / control ---------------------------------------------------- //
  getAudit: (tenantId: string, afterSequence = 0, limit = 50) =>
    adminFetch<AuditPageResponse>(`/admin/tenants/${encodeURIComponent(tenantId)}/audit`, {
      query: { after_sequence: afterSequence, limit },
    }),
  getConfig: (tenantId: string) =>
    adminFetch<ConfigResponse>(`/admin/tenants/${encodeURIComponent(tenantId)}/config`),
  updateConfig: (tenantId: string, body: ConfigUpdateRequest) =>
    adminFetch<ConfigResponse>(`/admin/tenants/${encodeURIComponent(tenantId)}/config`, {
      method: "PATCH",
      body,
    }),
  listPolicies: (tenantId: string, limit = 100, offset = 0) =>
    adminFetch<PolicyListResponse>(`/admin/tenants/${encodeURIComponent(tenantId)}/policies`, {
      query: { limit, offset },
    }),
};

export type AdminApi = typeof adminApi;
