import "server-only";

import { adminToken, deltaApiUrl } from "@/lib/env";
import { AdminApiError } from "@/lib/errors";
import type {
  AccessTokenCreateRequest,
  AccessTokenIssuedView,
  AccessTokenRevokeRequest,
  AccessTokenView,
  AllocationCreateRequest,
  AllocationStatus,
  AllocationView,
  AnomalyReportView,
  ApprovalDecisionRequest,
  AssetCreateRequest,
  AssetStatusTransitionRequest,
  AssetView,
  BottleneckReportView,
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
  ExecutiveSummaryView,
  ExternalSystemCreateRequest,
  ExternalSystemView,
  GroupSpendView,
  InteractionCreateRequest,
  InteractionView,
  InvoiceCreateRequest,
  InvoiceDecisionRequest,
  InvoicePaymentView,
  InvoiceStatus,
  InvoiceView,
  PaymentRecordRequest,
  PurchaseOrderCreateRequest,
  PurchaseOrderDecisionRequest,
  PurchaseOrderStatus,
  PurchaseOrderView,
  RebalanceReportView,
  RelationshipScoreView,
  SpendSummaryView,
  SprintCreateRequest,
  SprintStatusUpdateRequest,
  SprintView,
  StakeholderCreateRequest,
  StakeholderView,
  TaskAssignmentView,
  TaskCapacityView,
  TaskCreateRequest,
  TaskDependencyCreateRequest,
  TaskDependencyView,
  TaskStatus,
  TaskStatusUpdateRequest,
  SyncLineItemView,
  SyncRunCreateRequest,
  SyncRunView,
  SystemReconciliationView,
  TaskTeamAssignRequest,
  TaskView,
  TeamCapacityUpdateRequest,
  TeamCreateRequest,
  TeamView,
  TimeSeriesPointView,
  UtilizationReportView,
  VelocityReportView,
  VendorCreateRequest,
  VendorReconciliationView,
  VendorView,
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

  // D-014 ERP — a deliberately bounded vertical slice (asset register + vendor/
  // purchase-order procurement; no payroll, no HR, no external real-time sync).
  listVendors: (tenantId: string, limit?: number) =>
    adminFetch<VendorView[]>("/erp/vendors", { query: { tenant_id: tenantId, limit } }),

  createVendor: (body: VendorCreateRequest) =>
    adminFetch<VendorView>("/erp/vendors", { method: "POST", body }),

  listAssets: (tenantId: string, limit?: number) =>
    adminFetch<AssetView[]>("/erp/assets", { query: { tenant_id: tenantId, limit } }),

  createAsset: (body: AssetCreateRequest) =>
    adminFetch<AssetView>("/erp/assets", { method: "POST", body }),

  transitionAssetStatus: (assetId: string, body: AssetStatusTransitionRequest) =>
    adminFetch<AssetView>(`/erp/assets/${encodeURIComponent(assetId)}/status`, {
      method: "POST",
      body,
    }),

  listPurchaseOrders: (tenantId: string, status?: PurchaseOrderStatus, limit?: number) =>
    adminFetch<PurchaseOrderView[]>("/erp/purchase-orders", {
      query: { tenant_id: tenantId, status, limit },
    }),

  createPurchaseOrder: (body: PurchaseOrderCreateRequest) =>
    adminFetch<PurchaseOrderView>("/erp/purchase-orders", { method: "POST", body }),

  decidePurchaseOrder: (poId: string, body: PurchaseOrderDecisionRequest) =>
    adminFetch<PurchaseOrderView>(`/erp/purchase-orders/${encodeURIComponent(poId)}/decision`, {
      method: "POST",
      body,
    }),

  // D-015 project management — a deliberately bounded vertical slice (sprints,
  // tasks, a dependency graph, a velocity report, a deterministic blocking-fan-out
  // bottleneck heuristic; no push updates, no external issue-tracker sync, no ML).
  listSprints: (tenantId: string, projectId: string, limit?: number) =>
    adminFetch<SprintView[]>("/pm/sprints", {
      query: { tenant_id: tenantId, project_id: projectId, limit },
    }),

  createSprint: (body: SprintCreateRequest) =>
    adminFetch<SprintView>("/pm/sprints", { method: "POST", body }),

  updateSprintStatus: (sprintId: string, body: SprintStatusUpdateRequest) =>
    adminFetch<SprintView>(`/pm/sprints/${encodeURIComponent(sprintId)}/status`, {
      method: "POST",
      body,
    }),

  listTasks: (
    tenantId: string,
    projectId: string,
    opts: { sprintId?: string; status?: TaskStatus; limit?: number } = {},
  ) =>
    adminFetch<TaskView[]>("/pm/tasks", {
      query: {
        tenant_id: tenantId,
        project_id: projectId,
        sprint_id: opts.sprintId,
        status: opts.status,
        limit: opts.limit,
      },
    }),

  createTask: (body: TaskCreateRequest) => adminFetch<TaskView>("/pm/tasks", { method: "POST", body }),

  updateTaskStatus: (taskId: string, body: TaskStatusUpdateRequest) =>
    adminFetch<TaskView>(`/pm/tasks/${encodeURIComponent(taskId)}/status`, {
      method: "POST",
      body,
    }),

  createDependency: (body: TaskDependencyCreateRequest) =>
    adminFetch<TaskDependencyView>("/pm/dependencies", { method: "POST", body }),

  listTaskDependencies: (tenantId: string, taskId: string) =>
    adminFetch<TaskDependencyView[]>(`/pm/tasks/${encodeURIComponent(taskId)}/dependencies`, {
      query: { tenant_id: tenantId },
    }),

  getVelocityReport: (tenantId: string, projectId: string, limit?: number) =>
    adminFetch<VelocityReportView>("/pm/velocity", {
      query: { tenant_id: tenantId, project_id: projectId, limit },
    }),

  getBottleneckReport: (tenantId: string, projectId: string, limit?: number) =>
    adminFetch<BottleneckReportView>("/pm/bottlenecks", {
      query: { tenant_id: tenantId, project_id: projectId, limit },
    }),

  // D-016 team capacity — a deliberately bounded vertical slice (teams with an
  // operator-declared per-sprint capacity, task-to-team assignment, a deterministic
  // utilization report, an advisory-only rebalance suggestion; no individual-level
  // capacity/PTO data, no burnout/wellbeing signal, no automatic reassignment).
  listTeams: (tenantId: string, limit?: number) =>
    adminFetch<TeamView[]>("/capacity/teams", { query: { tenant_id: tenantId, limit } }),

  createTeam: (body: TeamCreateRequest) =>
    adminFetch<TeamView>("/capacity/teams", { method: "POST", body }),

  updateTeamCapacity: (teamId: string, body: TeamCapacityUpdateRequest) =>
    adminFetch<TeamView>(`/capacity/teams/${encodeURIComponent(teamId)}/capacity`, {
      method: "POST",
      body,
    }),

  listCapacityTasks: (tenantId: string, projectId: string, sprintId: string) =>
    adminFetch<TaskCapacityView[]>("/capacity/tasks", {
      query: { tenant_id: tenantId, project_id: projectId, sprint_id: sprintId },
    }),

  assignTaskTeam: (taskId: string, body: TaskTeamAssignRequest) =>
    adminFetch<TaskAssignmentView>(`/capacity/tasks/${encodeURIComponent(taskId)}/team`, {
      method: "POST",
      body,
    }),

  getUtilizationReport: (tenantId: string, projectId: string, sprintId: string) =>
    adminFetch<UtilizationReportView>("/capacity/utilization", {
      query: { tenant_id: tenantId, project_id: projectId, sprint_id: sprintId },
    }),

  getRebalanceReport: (tenantId: string, projectId: string, sprintId: string) =>
    adminFetch<RebalanceReportView>("/capacity/rebalance", {
      query: { tenant_id: tenantId, project_id: projectId, sprint_id: sprintId },
    }),

  // D-017 RBAC-gated dashboards — locally-issued, role-tagged bearer tokens
  // (tenant_admin/tenant_auditor), not real SSO/OIDC/SAML. Only the create call ever
  // returns the raw token value (one-time reveal).
  listAccessTokens: (tenantId: string, limit?: number) =>
    adminFetch<AccessTokenView[]>("/rbac/tokens", { query: { tenant_id: tenantId, limit } }),

  createAccessToken: (body: AccessTokenCreateRequest) =>
    adminFetch<AccessTokenIssuedView>("/rbac/tokens", { method: "POST", body }),

  revokeAccessToken: (tokenId: string, body: AccessTokenRevokeRequest) =>
    adminFetch<AccessTokenView>(`/rbac/tokens/${encodeURIComponent(tokenId)}/revoke`, {
      method: "POST",
      body,
    }),

  // D-018 automated invoicing + vendor payment reconciliation — a PO-backed
  // three-way match (purchase order -> invoice -> payment), not external ERP/bank
  // sync (that's D-019's job).
  listInvoices: (
    tenantId: string,
    filters?: { vendorId?: string; poId?: string; status?: InvoiceStatus },
    limit?: number,
  ) =>
    adminFetch<InvoiceView[]>("/invoicing/invoices", {
      query: {
        tenant_id: tenantId,
        vendor_id: filters?.vendorId,
        po_id: filters?.poId,
        status: filters?.status,
        limit,
      },
    }),

  createInvoice: (body: InvoiceCreateRequest) =>
    adminFetch<InvoiceView>("/invoicing/invoices", { method: "POST", body }),

  decideInvoice: (invoiceId: string, body: InvoiceDecisionRequest) =>
    adminFetch<InvoiceView>(`/invoicing/invoices/${encodeURIComponent(invoiceId)}/decision`, {
      method: "POST",
      body,
    }),

  recordInvoicePayment: (invoiceId: string, body: PaymentRecordRequest) =>
    adminFetch<InvoicePaymentView>(`/invoicing/invoices/${encodeURIComponent(invoiceId)}/payments`, {
      method: "POST",
      body,
    }),

  listInvoicePayments: (tenantId: string, invoiceId: string, limit?: number) =>
    adminFetch<InvoicePaymentView[]>(
      `/invoicing/invoices/${encodeURIComponent(invoiceId)}/payments`,
      { query: { tenant_id: tenantId, limit } },
    ),

  getVendorReconciliation: (tenantId: string, vendorId: string, currency?: string) =>
    adminFetch<VendorReconciliationView>("/invoicing/reconciliation", {
      query: { tenant_id: tenantId, vendor_id: vendorId, currency },
    }),

  // D-019 corporate ERP/procurement/cloud-cost sync connectors — a generic
  // registration + sync-ingestion + reconciliation-matching framework, not live
  // OAuth/API integrations with NetSuite/SAP/Coupa/Ariba/AWS/GCP/Azure.
  listExternalSystems: (tenantId: string, limit?: number) =>
    adminFetch<ExternalSystemView[]>("/integrations/systems", {
      query: { tenant_id: tenantId, limit },
    }),

  createExternalSystem: (body: ExternalSystemCreateRequest) =>
    adminFetch<ExternalSystemView>("/integrations/systems", { method: "POST", body }),

  runSync: (systemId: string, body: SyncRunCreateRequest) =>
    adminFetch<SyncRunView>(`/integrations/systems/${encodeURIComponent(systemId)}/sync`, {
      method: "POST",
      body,
    }),

  listSyncRuns: (tenantId: string, systemId: string, limit?: number) =>
    adminFetch<SyncRunView[]>(`/integrations/systems/${encodeURIComponent(systemId)}/sync-runs`, {
      query: { tenant_id: tenantId, limit },
    }),

  listSyncLineItems: (tenantId: string, syncRunId: string, limit?: number) =>
    adminFetch<SyncLineItemView[]>(
      `/integrations/sync-runs/${encodeURIComponent(syncRunId)}/line-items`,
      { query: { tenant_id: tenantId, limit } },
    ),

  getSystemReconciliation: (tenantId: string, systemId: string) =>
    adminFetch<SystemReconciliationView>(
      `/integrations/systems/${encodeURIComponent(systemId)}/reconciliation`,
      { query: { tenant_id: tenantId } },
    ),

  // D-020 executive financial dashboard — a pure read-only rollup composing D-008
  // spend, D-011 forecasts, and D-013 pipeline via their own service functions.
  getExecutiveSummary: (tenantId: string, start: string, end: string) =>
    adminFetch<ExecutiveSummaryView>("/executive/summary", {
      query: { tenant_id: tenantId, start, end },
    }),
};

export type AdminApi = typeof adminApi;
