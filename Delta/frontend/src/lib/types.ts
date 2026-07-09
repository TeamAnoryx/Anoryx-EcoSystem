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

/**
 * D-012 chargeback/showback + anomaly detection (Delta/src/delta/chargeback/schemas.py).
 * Figures are the same client-side cost estimates the rest of Delta already is —
 * informational cost-attribution, never an authoritative bill or invoice.
 */
export interface ChargebackRow {
  group_key: string;
  cost_cents: number;
  request_count: number;
  share_pct: number;
}

export interface ChargebackReportView {
  total_cost_cents: number;
  rows: ChargebackRow[];
}

export type AnomalyCode = "SPEND_SPIKE" | "NEW_SPENDER";
export type AnomalySeverity = "info" | "warning";

export interface AnomalyRow {
  group_key: string;
  current_spend_cents: number;
  baseline_avg_cents: number;
  ratio: number | null;
  code: AnomalyCode;
  severity: AnomalySeverity;
}

export interface AnomalyReportView {
  baseline_periods: number;
  baseline_start: string;
  baseline_end: string;
  anomalies: AnomalyRow[];
  /** A fixed-multiple trailing-average comparison, not a trained/validated
   * statistical or ML model — see docs/adr/0012-delta-chargeback-anomaly-detection.md. */
  method: "trailing_average_ratio_v1";
}

/**
 * D-013 unified CRM (Delta/src/delta/crm/schemas.py). A deliberately bounded vertical
 * slice — client records, a deal pipeline, a stakeholder roster, an interaction
 * history, and a deterministic relationship-score heuristic. See
 * docs/adr/0013-delta-unified-crm.md.
 */
export type DealStage = "lead" | "qualified" | "proposal" | "negotiation" | "won" | "lost";
export type InteractionType = "call" | "email" | "meeting" | "note";
export type StakeholderRole = "decision_maker" | "influencer" | "champion" | "blocker" | "unknown";

export interface ClientCreateRequest {
  tenant_id: string;
  name: string;
  primary_contact_name?: string | null;
  primary_contact_email?: string | null;
}

export interface ClientView {
  client_id: string;
  tenant_id: string;
  name: string;
  primary_contact_name: string | null;
  primary_contact_email: string | null;
  created_at: string;
  updated_at: string;
}

export interface DealCreateRequest {
  tenant_id: string;
  name: string;
  value_minor_units?: number | null;
  currency?: string | null;
  expected_close_date?: string | null;
}

export interface DealStageTransitionRequest {
  tenant_id: string;
  stage: DealStage;
  actor: string;
}

export interface DealView {
  deal_id: string;
  client_id: string;
  tenant_id: string;
  name: string;
  stage: DealStage;
  value_minor_units: number | null;
  currency: string | null;
  expected_close_date: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface InteractionCreateRequest {
  tenant_id: string;
  deal_id?: string | null;
  stakeholder_id?: string | null;
  interaction_type: InteractionType;
  occurred_at: string;
  summary: string;
  created_by: string;
}

export interface InteractionView {
  interaction_id: string;
  client_id: string;
  deal_id: string | null;
  stakeholder_id: string | null;
  tenant_id: string;
  interaction_type: InteractionType;
  occurred_at: string;
  summary: string;
  created_by: string;
  created_at: string;
}

export interface StakeholderCreateRequest {
  tenant_id: string;
  deal_id?: string | null;
  name: string;
  role?: StakeholderRole;
  email?: string | null;
}

export interface StakeholderView {
  stakeholder_id: string;
  client_id: string;
  deal_id: string | null;
  tenant_id: string;
  name: string;
  role: StakeholderRole;
  email: string | null;
  created_at: string;
  updated_at: string;
  /** Computed live from `interactions` tagged to this stakeholder — never stored,
   * never NLP-extracted from free text (ADR-0013 Fork 3). */
  interaction_count: number;
  last_interaction_at: string | null;
}

export interface RelationshipScoreView {
  client_id: string;
  score: number;
  interaction_count_90d: number;
  days_since_last_interaction: number | null;
  open_deal_count: number;
  /** A deterministic recency + frequency heuristic, not a trained/validated
   * statistical or ML model — see docs/adr/0013-delta-unified-crm.md. */
  method: "recency_frequency_v1";
}

export interface ClientDetailView {
  client: ClientView;
  deals: DealView[];
  recent_interactions: InteractionView[];
  stakeholders: StakeholderView[];
  relationship_score: RelationshipScoreView;
}
