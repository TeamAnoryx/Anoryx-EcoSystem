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

/**
 * D-014 ERP: asset register + vendor/purchase-order procurement
 * (Delta/src/delta/erp/schemas.py). A deliberately bounded vertical slice — no
 * payroll, no HR, no external real-time sync (that's D-019's job). See
 * docs/adr/0014-delta-erp-assets-procurement.md.
 */
export type AssetCategory = "equipment" | "software_license" | "furniture" | "vehicle" | "other";
export type AssetStatus = "active" | "retired" | "disposed";
export type VendorStatus = "active" | "inactive";
export type PurchaseOrderStatus = "requested" | "approved" | "rejected";
export type PurchaseOrderAction = "approve" | "reject";

export interface VendorCreateRequest {
  tenant_id: string;
  name: string;
  contact_email?: string | null;
}

export interface VendorView {
  vendor_id: string;
  tenant_id: string;
  name: string;
  contact_email: string | null;
  status: VendorStatus;
  created_at: string;
  updated_at: string;
}

export interface AssetCreateRequest {
  tenant_id: string;
  name: string;
  category: AssetCategory;
  acquisition_cost_minor_units?: number | null;
  currency?: string | null;
  acquired_at?: string | null;
  assigned_team_id?: string | null;
}

export interface AssetStatusTransitionRequest {
  tenant_id: string;
  status: AssetStatus;
  actor: string;
}

export interface AssetView {
  asset_id: string;
  tenant_id: string;
  name: string;
  category: AssetCategory;
  status: AssetStatus;
  acquisition_cost_minor_units: number | null;
  currency: string | null;
  acquired_at: string | null;
  assigned_team_id: string | null;
  retired_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface PurchaseOrderCreateRequest {
  tenant_id: string;
  vendor_id: string;
  asset_id?: string | null;
  description: string;
  amount_minor_units: number;
  currency?: string;
  requested_by: string;
}

export interface PurchaseOrderDecisionRequest {
  tenant_id: string;
  action: PurchaseOrderAction;
  actor: string;
  note?: string | null;
}

export interface PurchaseOrderView {
  po_id: string;
  tenant_id: string;
  vendor_id: string;
  asset_id: string | null;
  description: string;
  amount_minor_units: number;
  currency: string;
  status: PurchaseOrderStatus;
  requested_by: string;
  requested_at: string;
  decided_by: string | null;
  decided_at: string | null;
}

/**
 * D-015 project management: sprints, tasks, a dependency graph, sprint velocity,
 * and a deterministic blocking-fan-out bottleneck heuristic
 * (Delta/src/delta/pm/schemas.py). Not the roadmap's literal "real-time... AI-driven
 * execution-bottleneck prediction" — no push updates, no trained/validated ML. See
 * docs/adr/0015-delta-pm-sprints-dependencies.md.
 */
export type SprintStatus = "planned" | "active" | "completed";
export type TaskStatus = "todo" | "in_progress" | "done" | "blocked";

export interface SprintCreateRequest {
  tenant_id: string;
  project_id: string;
  name: string;
  start_date: string;
  end_date: string;
}

export interface SprintStatusUpdateRequest {
  tenant_id: string;
  status: SprintStatus;
}

export interface SprintView {
  sprint_id: string;
  tenant_id: string;
  project_id: string;
  name: string;
  start_date: string;
  end_date: string;
  status: SprintStatus;
  created_at: string;
  updated_at: string;
}

export interface TaskCreateRequest {
  tenant_id: string;
  project_id: string;
  sprint_id?: string | null;
  title: string;
  story_points?: number | null;
  assignee?: string | null;
}

export interface TaskStatusUpdateRequest {
  tenant_id: string;
  status: TaskStatus;
}

export interface TaskView {
  task_id: string;
  tenant_id: string;
  project_id: string;
  sprint_id: string | null;
  title: string;
  status: TaskStatus;
  story_points: number | null;
  assignee: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}

export interface TaskDependencyCreateRequest {
  tenant_id: string;
  blocking_task_id: string;
  blocked_task_id: string;
}

export interface TaskDependencyView {
  dependency_id: string;
  tenant_id: string;
  blocking_task_id: string;
  blocked_task_id: string;
  created_at: string;
}

export interface SprintVelocityRow {
  sprint_id: string;
  sprint_name: string;
  status: SprintStatus;
  completed_story_points: number;
  completed_task_count: number;
  total_task_count: number;
}

export interface VelocityReportView {
  project_id: string;
  sprints: SprintVelocityRow[];
}

export interface BottleneckRow {
  task_id: string;
  title: string;
  status: TaskStatus;
  blocking_count: number;
}

export interface BottleneckReportView {
  project_id: string;
  bottlenecks: BottleneckRow[];
  /** A deterministic blocking-fan-out ranking, not a trained/validated statistical
   * or ML prediction model — see docs/adr/0015-delta-pm-sprints-dependencies.md. */
  method: "blocking_fanout_v1";
}

/**
 * D-016 team capacity management: teams, task-to-team assignment, a deterministic
 * utilization report, and an advisory (never automatic) rebalancing suggestion
 * (Delta/src/delta/capacity/schemas.py). Not the roadmap's literal "squad
 * performance... automated resource allocation... real-time utilization to prevent
 * burnout" — no individual-level capacity/PTO data, no burnout/wellbeing signal, no
 * automatic task reassignment, no real-time push. See
 * docs/adr/0016-delta-team-capacity-management.md.
 */
export interface TeamCreateRequest {
  tenant_id: string;
  name: string;
  capacity_points_per_sprint: number;
}

export interface TeamCapacityUpdateRequest {
  tenant_id: string;
  capacity_points_per_sprint: number;
}

export interface TeamView {
  team_id: string;
  tenant_id: string;
  name: string;
  capacity_points_per_sprint: number;
  created_at: string;
  updated_at: string;
}

export interface TaskTeamAssignRequest {
  tenant_id: string;
  team_id?: string | null;
}

export interface TaskAssignmentView {
  task_id: string;
  tenant_id: string;
  team_id: string | null;
}

/** A task's capacity-relevant fields for one sprint — `TaskView` (D-015) does not
 * expose `team_id`, so the capacity UI reads through `/capacity/tasks` instead of
 * `/pm/tasks` whenever it needs a task's current team assignment. */
export interface TaskCapacityView {
  task_id: string;
  title: string;
  status: string;
  story_points: number | null;
  team_id: string | null;
}

export interface UtilizationRow {
  team_id: string;
  team_name: string;
  capacity_points_per_sprint: number;
  total_assigned_points: number;
  remaining_points: number;
  utilization_ratio: number | null;
}

export interface UtilizationReportView {
  project_id: string;
  sprint_id: string;
  teams: UtilizationRow[];
  /** A deterministic ratio, not a trained/validated statistical or ML prediction —
   * see docs/adr/0016-delta-team-capacity-management.md. */
  method: "capacity_ratio_v1";
}

export interface RebalanceSuggestion {
  task_id: string;
  title: string;
  story_points: number;
  from_team_id: string;
  from_team_name: string;
  to_team_id: string;
  to_team_name: string;
}

export interface RebalanceReportView {
  project_id: string;
  sprint_id: string;
  suggestions: RebalanceSuggestion[];
  /** A deterministic greedy suggestion, purely advisory — nothing is moved
   * automatically. See docs/adr/0016-delta-team-capacity-management.md. */
  method: "greedy_rebalance_v1";
}

/**
 * D-017 RBAC-gated dashboards: locally-issued, role-tagged bearer tokens
 * (Delta/src/delta/rbac/schemas.py). NOT real SSO/OIDC/SAML (that's Anoryx-
 * Sentinel's already-shipped F-014) — a two-role model (`tenant_admin`/
 * `tenant_auditor`, mirroring Sentinel's own role vocabulary for ecosystem naming
 * consistency) gating D-008's dashboards, the ONE existing admin surface this task
 * retrofits. See docs/adr/0017-delta-rbac-dashboards.md.
 */
export type AccessRole = "tenant_admin" | "tenant_auditor";

export interface AccessTokenCreateRequest {
  tenant_id: string;
  name: string;
  role: AccessRole;
}

export interface AccessTokenRevokeRequest {
  tenant_id: string;
}

export interface AccessTokenView {
  token_id: string;
  tenant_id: string;
  name: string;
  role: AccessRole;
  created_at: string;
  revoked_at: string | null;
}

/** The one-time reveal of a newly-issued token's raw value — returned ONLY by the
 * create call, never again. */
export interface AccessTokenIssuedView extends AccessTokenView {
  token: string;
}

/**
 * D-018 automated invoicing + vendor payment reconciliation
 * (Delta/src/delta/invoicing/schemas.py). An accounts-payable three-way match — a
 * D-014 purchase order (commitment) -> invoice (billing claim, optionally proven by
 * a D-015 task's 'done' status as the delivery-metric leg) -> recorded payments
 * (settlement) — plus a computed per-vendor reconciliation report. Does NOT wire
 * vendor payments into D-003's ledger (that ledger is scoped to AI-usage cost
 * attribution, not accounts-payable); real external ERP/bank-feed sync is D-019's
 * job. See docs/adr/0018-delta-invoicing-reconciliation.md.
 */
export type InvoiceStatus = "submitted" | "approved" | "disputed" | "partially_paid" | "paid";
export type InvoiceDecisionAction = "approve" | "dispute";

export interface InvoiceCreateRequest {
  tenant_id: string;
  vendor_id: string;
  po_id: string;
  milestone_task_id?: string | null;
  invoice_number: string;
  description: string;
  amount_minor_units: number;
  currency?: string;
  submitted_by: string;
}

export interface InvoiceDecisionRequest {
  tenant_id: string;
  action: InvoiceDecisionAction;
  actor: string;
  note?: string | null;
}

export interface InvoiceView {
  invoice_id: string;
  tenant_id: string;
  vendor_id: string;
  po_id: string;
  milestone_task_id: string | null;
  invoice_number: string;
  description: string;
  amount_minor_units: number;
  currency: string;
  amount_paid_minor_units: number;
  status: InvoiceStatus;
  submitted_by: string;
  submitted_at: string;
  decided_by: string | null;
  decided_at: string | null;
}

export interface PaymentRecordRequest {
  tenant_id: string;
  amount_minor_units: number;
  currency?: string;
  paid_at: string;
  recorded_by: string;
  note?: string | null;
}

export interface InvoicePaymentView {
  payment_id: string;
  tenant_id: string;
  invoice_id: string;
  amount_minor_units: number;
  currency: string;
  paid_at: string;
  recorded_by: string;
  note: string | null;
}

/** Defense-in-depth reconciliation flags: the create/pay guards already make
 * `over_invoiced`/`over_paid` structurally impossible, so a `true` here would mean
 * those guards were bypassed or a data-layer bug exists — see ADR-0018 §4. */
export interface VendorReconciliationView {
  vendor_id: string;
  currency: string;
  committed_minor_units: number;
  invoiced_minor_units: number;
  paid_minor_units: number;
  outstanding_minor_units: number;
  disputed_invoice_count: number;
  over_invoiced: boolean;
  over_paid: boolean;
}

/**
 * D-019 corporate ERP/procurement/cloud-cost sync connectors
 * (Delta/src/delta/integrations/schemas.py). A generic external-system
 * registration + sync-ingestion + reconciliation-matching FRAMEWORK — NOT seven live
 * OAuth/API integrations with NetSuite/SAP/Coupa/Ariba/AWS/GCP/Azure. Each ingested
 * line item is matched against a D-014 purchase order or D-018 invoice by exact ID +
 * amount/currency comparison. See docs/adr/0019-delta-erp-integrations.md.
 */
export type SystemType = "corporate_erp" | "procurement" | "cloud_cost";
export type SystemStatus = "active" | "disabled";
export type MatchedStatus = "matched" | "amount_mismatch" | "not_found" | "unreconciled";
export type MatchedEntityType = "purchase_order" | "invoice";

export interface ExternalSystemCreateRequest {
  tenant_id: string;
  name: string;
  system_type: SystemType;
  vendor_label: string;
}

export interface ExternalSystemView {
  system_id: string;
  tenant_id: string;
  name: string;
  system_type: SystemType;
  vendor_label: string;
  status: SystemStatus;
  created_at: string;
  updated_at: string;
}

export interface SyncLineItemInput {
  external_reference: string;
  amount_minor_units: number;
  currency: string;
  po_id?: string | null;
  invoice_id?: string | null;
}

export interface SyncRunCreateRequest {
  tenant_id: string;
  triggered_by: string;
  note?: string | null;
  line_items: SyncLineItemInput[];
}

export interface SyncRunView {
  sync_run_id: string;
  tenant_id: string;
  system_id: string;
  triggered_by: string;
  started_at: string;
  completed_at: string;
  records_ingested: number;
  records_matched: number;
  records_mismatched: number;
  records_not_found: number;
  records_unreconciled: number;
  note: string | null;
}

export interface SyncLineItemView {
  line_item_id: string;
  tenant_id: string;
  sync_run_id: string;
  external_reference: string;
  amount_minor_units: number;
  currency: string;
  matched_status: MatchedStatus;
  matched_entity_type: MatchedEntityType | null;
  matched_entity_id: string | null;
}

export interface SystemReconciliationView {
  system_id: string;
  total_runs: number;
  matched_count: number;
  mismatched_count: number;
  not_found_count: number;
  unreconciled_count: number;
  mismatched_amount_minor_units: number;
}

/**
 * D-020 executive financial dashboard (Delta/src/delta/executive/schemas.py).
 * Read-only rollup composing D-008 spend, D-011 forecasts, and D-013 pipeline —
 * no request/mutation shapes, only a view.
 */
export interface ExecutiveSummaryView {
  tenant_id: string;
  period_start: string;
  period_end: string;
  generated_at: string;
  total_cost_cents: number;
  request_count: number;
  burn_rate_cents_per_hour: number;
  budget_count: number;
  /** true iff budget_count hit the forecast rollup's cap — figures below may under-count. */
  budgets_truncated: boolean;
  total_current_period_spend_cents: number;
  /** null when no forecast has enough data to project (D-011's own contract). */
  total_projected_period_end_spend_cents: number | null;
  budgets_at_critical: number;
  budgets_at_warning: number;
  budgets_insufficient_data: number;
  client_count: number;
  open_deal_count: number;
  open_pipeline_value_minor_units: number;
  pipeline_currency: string;
}

/**
 * D-021 personal-finance (B2C track, Delta/src/delta/personal_finance/schemas.py).
 * A B2C consumer IS one tenant_id (ADR-0021 Fork 1) — no separate consumer-identity
 * shape. New, structurally separate from D-003's AI-cost ledger (ADR-0021 Fork 2).
 */
export type PersonalAccountType = "checking" | "savings" | "credit_card" | "cash" | "investment";
export type PersonalTransactionCategory =
  | "groceries"
  | "rent"
  | "utilities"
  | "dining"
  | "transport"
  | "entertainment"
  | "subscriptions"
  | "healthcare"
  | "income"
  | "transfer"
  | "other";
export type PersonalBudgetCategory = Exclude<PersonalTransactionCategory, "income" | "transfer">;

export interface AccountCreateRequest {
  tenant_id: string;
  type: PersonalAccountType;
  currency: string;
  name: string;
}

export interface AccountView {
  account_id: string;
  tenant_id: string;
  type: PersonalAccountType;
  currency: string;
  name: string;
  created_at: string;
}

export interface TransactionCreateRequest {
  tenant_id: string;
  account_id: string;
  category: PersonalTransactionCategory;
  /** Negative = expense, positive = income. */
  amount_minor_units: number;
  currency: string;
  description?: string;
  merchant?: string | null;
  occurred_at: string;
}

export interface TransactionView {
  txn_id: string;
  tenant_id: string;
  account_id: string;
  category: PersonalTransactionCategory;
  amount_minor_units: number;
  currency: string;
  description: string;
  merchant: string | null;
  occurred_at: string;
  created_at: string;
  source: "manual";
}

export interface BudgetCreateRequest {
  tenant_id: string;
  category: PersonalBudgetCategory;
  cap_minor_units: number;
  currency: string;
  period?: "monthly";
}

export interface BudgetView {
  budget_id: string;
  tenant_id: string;
  category: PersonalBudgetCategory;
  cap_minor_units: number;
  currency: string;
  period: "monthly";
  created_at: string;
}

export interface BudgetStatusView {
  category: PersonalBudgetCategory;
  cap_minor_units: number;
  spent_minor_units: number;
  currency: string;
  over_cap: boolean;
}

export interface FinancialHealthView {
  tenant_id: string;
  period_start: string;
  period_end: string;
  generated_at: string;
  currency: string;
  total_income_minor_units: number;
  total_expense_minor_units: number;
  /** null iff total_income_minor_units is 0 (never a divide-by-zero placeholder). */
  savings_rate: number | null;
  budgets: BudgetStatusView[];
  /** A deterministic heuristic score (0-100), NOT machine learning / AI. */
  health_score: number;
}
