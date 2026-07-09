import "server-only";

import { adminToken, deltaApiUrl } from "@/lib/env";
import { AdminApiError } from "@/lib/errors";
import type {
  AllocationCreateRequest,
  AllocationStatus,
  AllocationView,
  AnomalyReportView,
  ApprovalDecisionRequest,
  ChangeHistoryEntryView,
  ChargebackReportView,
  ClientCreateRequest,
  ClientDetailView,
  ClientView,
  DashboardBucket,
  DashboardGroupDimension,
  DashboardScope,
  DealCreateRequest,
  DealStageTransitionRequest,
  DealView,
  GroupSpendView,
  InteractionCreateRequest,
  InteractionView,
  RelationshipScoreView,
  SpendSummaryView,
  StakeholderCreateRequest,
  StakeholderView,
  TimeSeriesPointView,
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

  // D-008 dashboards — read-only, RFC3339 start/end (UTC), optional team/project/
  // agent scope narrows the window before aggregation ("client/team-set parameters").
  getSummary: (tenantId: string, start: string, end: string, scope: DashboardScope = {}) =>
    adminFetch<SpendSummaryView>("/dashboards/summary", {
      query: {
        tenant_id: tenantId,
        start,
        end,
        team_id: scope.team_id,
        project_id: scope.project_id,
        agent_id: scope.agent_id,
      },
    }),

  getTimeSeries: (
    tenantId: string,
    start: string,
    end: string,
    bucket: DashboardBucket = "day",
    scope: DashboardScope = {},
  ) =>
    adminFetch<TimeSeriesPointView[]>("/dashboards/timeseries", {
      query: {
        tenant_id: tenantId,
        start,
        end,
        bucket,
        team_id: scope.team_id,
        project_id: scope.project_id,
        agent_id: scope.agent_id,
      },
    }),

  getTopSpenders: (
    tenantId: string,
    start: string,
    end: string,
    groupBy: DashboardGroupDimension,
    limit = 10,
    scope: DashboardScope = {},
  ) =>
    adminFetch<GroupSpendView[]>("/dashboards/top-spenders", {
      query: {
        tenant_id: tenantId,
        start,
        end,
        group_by: groupBy,
        limit,
        team_id: scope.team_id,
        project_id: scope.project_id,
        agent_id: scope.agent_id,
      },
    }),

  // D-012 chargeback/showback + anomaly detection — same RFC3339 start/end (UTC) +
  // scope shape as the D-008 dashboards, group_by is required (not optional-with-
  // default like getTopSpenders — a chargeback report always needs a department axis).
  getChargebackReport: (
    tenantId: string,
    start: string,
    end: string,
    groupBy: DashboardGroupDimension,
    scope: DashboardScope = {},
  ) =>
    adminFetch<ChargebackReportView>("/chargeback/report", {
      query: {
        tenant_id: tenantId,
        start,
        end,
        group_by: groupBy,
        team_id: scope.team_id,
        project_id: scope.project_id,
        agent_id: scope.agent_id,
      },
    }),

  getAnomalies: (
    tenantId: string,
    start: string,
    end: string,
    groupBy: DashboardGroupDimension,
    baselinePeriods = 7,
    scope: DashboardScope = {},
  ) =>
    adminFetch<AnomalyReportView>("/chargeback/anomalies", {
      query: {
        tenant_id: tenantId,
        start,
        end,
        group_by: groupBy,
        baseline_periods: baselinePeriods,
        team_id: scope.team_id,
        project_id: scope.project_id,
        agent_id: scope.agent_id,
      },
    }),

  // D-013 unified CRM — a deliberately bounded vertical slice (client records, a
  // deal pipeline, a stakeholder roster, an interaction history, a relationship
  // score). Same per-target tenant_id shape as every other admin surface.
  listClients: (tenantId: string, limit?: number) =>
    adminFetch<ClientView[]>("/crm/clients", { query: { tenant_id: tenantId, limit } }),

  createClient: (body: ClientCreateRequest) =>
    adminFetch<ClientView>("/crm/clients", { method: "POST", body }),

  getClientDetail: (tenantId: string, clientId: string) =>
    adminFetch<ClientDetailView>(`/crm/clients/${encodeURIComponent(clientId)}`, {
      query: { tenant_id: tenantId },
    }),

  createDeal: (clientId: string, body: DealCreateRequest) =>
    adminFetch<DealView>(`/crm/clients/${encodeURIComponent(clientId)}/deals`, {
      method: "POST",
      body,
    }),

  transitionDealStage: (dealId: string, body: DealStageTransitionRequest) =>
    adminFetch<DealView>(`/crm/deals/${encodeURIComponent(dealId)}/stage`, {
      method: "POST",
      body,
    }),

  createStakeholder: (clientId: string, body: StakeholderCreateRequest) =>
    adminFetch<StakeholderView>(`/crm/clients/${encodeURIComponent(clientId)}/stakeholders`, {
      method: "POST",
      body,
    }),

  createInteraction: (clientId: string, body: InteractionCreateRequest) =>
    adminFetch<InteractionView>(`/crm/clients/${encodeURIComponent(clientId)}/interactions`, {
      method: "POST",
      body,
    }),

  getRelationshipScore: (tenantId: string, clientId: string) =>
    adminFetch<RelationshipScoreView>(
      `/crm/clients/${encodeURIComponent(clientId)}/relationship-score`,
      { query: { tenant_id: tenantId } },
    ),
};

export type AdminApi = typeof adminApi;
