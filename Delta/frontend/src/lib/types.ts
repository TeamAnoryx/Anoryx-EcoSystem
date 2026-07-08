/**
 * TypeScript mirror of the `/v1/admin/*` request/response models
 * (Delta/src/delta/allocation_admin/schemas.py — D-007). Hand-written for
 * determinism + zero codegen dependency (mirrors Sentinel's src/lib/types.ts
 * convention). The FastAPI app exposes no OpenAPI schema (`openapi_url=None`),
 * so schemas.py is the source of truth — keep this file in lockstep with it.
 *
 * Money fields are ALWAYS integer minor units (cents). Never round-trip a
 * human dollar amount back into any of these shapes as a float.
 */

export type BudgetScope = "tenant" | "team" | "project" | "agent";
export type BudgetPeriod = "hourly" | "daily" | "monthly";
export type AllocationStatus = "requested" | "approved" | "rejected";
export type ApprovalAction = "approve" | "reject";

export interface AllocationTargetIn {
  scope: BudgetScope;
  team_id: string;
  project_id: string;
  agent_id: string;
  amount_minor_units: number;
}

export interface AllocationCreateRequest {
  tenant_id: string;
  total_minor_units: number;
  currency: string;
  period: BudgetPeriod;
  targets: AllocationTargetIn[];
  requested_by: string;
}

export interface AllocationTargetView {
  scope: BudgetScope;
  team_id: string;
  project_id: string;
  agent_id: string;
  amount_minor_units: number;
  /** Set only once the allocation is approved (materialized into a real budget cap). */
  budget_id: string | null;
}

export interface AllocationView {
  allocation_id: string;
  tenant_id: string;
  total_minor_units: number;
  currency: string;
  period: BudgetPeriod;
  status: AllocationStatus;
  requested_by: string;
  requested_at: string;
  decided_by: string | null;
  decided_at: string | null;
  targets: AllocationTargetView[];
}

export interface ApprovalDecisionRequest {
  tenant_id: string;
  action: ApprovalAction;
  actor: string;
  note?: string | null;
}

export interface ChangeHistoryEntryView {
  history_id: string;
  tenant_id: string;
  entity_type: string;
  entity_id: string;
  action: string;
  actor: string;
  note: string | null;
  created_at: string;
}

/**
 * D-008 dashboards (Delta/src/delta/dashboards/schemas.py). Read-only aggregates
 * over the D-003 ledger — no request/mutation shapes, only views.
 */
export type DashboardGroupDimension = "team_id" | "project_id" | "agent_id";
export type DashboardBucket = "hour" | "day";

export interface DashboardScope {
  team_id?: string;
  project_id?: string;
  agent_id?: string;
}

export interface SpendSummaryView {
  total_cost_cents: number;
  request_count: number;
  /** null when request_count is 0 (never a divide-by-zero placeholder). */
  cost_per_request_cents: number | null;
  burn_rate_cents_per_hour: number;
}

export interface TimeSeriesPointView {
  bucket_start: string;
  cost_cents: number;
  request_count: number;
}

export interface GroupSpendView {
  group_key: string;
  cost_cents: number;
  request_count: number;
}
