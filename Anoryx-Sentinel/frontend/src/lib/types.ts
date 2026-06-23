/**
 * TypeScript mirror of the `/admin/*` request/response models
 * (contracts/openapi.yaml components; src/admin/schemas.py). Hand-written for
 * determinism + zero codegen dependency (ADR-0015 D8). Keep in lockstep with the
 * contract — the contract is the source of truth.
 */

export interface TenantResponse {
  tenant_id: string;
  name: string;
  display_name: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface TenantListResponse {
  tenants: TenantResponse[];
  count: number;
}

export interface TenantCreateRequest {
  name: string;
  display_name?: string | null;
}

export interface KeyResponse {
  key_id: string;
  tenant_id: string;
  team_id: string;
  project_id: string;
  agent_id: string;
  label: string | null;
  is_active: boolean;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
}

export interface KeyListResponse {
  keys: KeyResponse[];
  count: number;
}

export interface KeyMintRequest {
  team_id: string;
  project_id: string;
  agent_id: string;
  label?: string | null;
  expires_at?: string | null;
}

/** `secret` is the plaintext key — present EXACTLY ONCE on mint/rotate (R5). */
export interface KeyMintResponse {
  secret: string;
  key: KeyResponse;
}

export interface AuditEventResponse {
  sequence_number: number;
  event_id: string;
  event_type: string;
  event_timestamp: string;
  request_id: string;
  tenant_id: string;
  team_id: string;
  project_id: string;
  agent_id: string;
  action_taken: string | null;
  prev_hash: string;
  row_hash: string;
}

export interface AuditPageResponse {
  events: AuditEventResponse[];
  count: number;
  next_cursor: number | null;
  /** F-003 hash-chain verification status — surfaced honestly. */
  chain_verified: boolean;
  chain_rows_checked: number;
}

export interface ConfigResponse {
  tenant_id: string;
  classifier_model_id: string | null;
  audit_mode: string | null;
  team_rpm_limit: number | null;
  configured: boolean;
}

export interface ConfigUpdateRequest {
  classifier_model_id?: string | null;
  audit_mode?: string | null;
  team_rpm_limit?: number | null;
}

export interface PolicyResponse {
  policy_id: string;
  policy_type: string;
  current_version: number;
  effective_from: string;
  team_id: string;
  project_id: string;
  agent_id: string;
  created_at: string;
}

export interface PolicyListResponse {
  policies: PolicyResponse[];
  count: number;
}

export interface WhoamiResponse {
  principal: string;
}

/**
 * Operator compliance-evidence request (F-011 path via control.py). framework is
 * "SOC2" | "ISO27001"; t0/t1 are RFC3339 UTC bounds of a half-open window.
 */
export interface OperatorEvidenceRequest {
  framework: string;
  t0: string;
  t1: string;
}

export interface OperatorEvidenceTotals {
  total: number;
  passed: number;
  gap: number;
  not_applicable: number;
  not_covered: number;
  applicable: number;
}

/**
 * Operator compliance-evidence response (mirror of control.py
 * operator_generate_evidence dict). Aggregate totals + readiness ONLY — the
 * per-control list is not exposed by this endpoint (F-013 ADR-0016 deferral 2b).
 */
export interface OperatorEvidenceResponse {
  tenant_id: string;
  framework: string;
  framework_version: string;
  window: { t0: string; t1: string };
  readiness_score: number;
  totals: OperatorEvidenceTotals;
  disclaimer: string;
}

// --- F-018 shadow-AI candidate types --------------------------------------- //

/**
 * A single shadow-AI review candidate from
 * `GET /tenants/{id}/shadow-ai/candidates`. Each row is a grouped detection
 * — disallowed known-provider egress through Sentinel — enriched with a
 * confidence band and the fired signals that produced it. Never a verdict.
 * (ADR-0021 §8)
 */
export interface ShadowAiCandidate {
  team_id: string;
  project_id: string;
  endpoint: string;
  provider: string;
  call_count: number;
  first_seen: string;
  last_seen: string;
  /** "low" | "medium" | "high" — how confident the heuristic is. */
  confidence_band: "low" | "medium" | "high";
  /** The explainable signals that fired (e.g. ["disallowed_provider", "volume"]). */
  fired_signals: string[];
  /** Always "candidate" — the backend enforces this (R3: never "verdict"). */
  label: "candidate";
}

/**
 * Response envelope for `GET /tenants/{id}/shadow-ai/candidates`.
 * `disclaimer` is the honesty boundary text from `HONESTY_DISCLAIMER` in the
 * backend constants — it must be rendered verbatim and non-removably (ADR-0021
 * §4 / R1).
 */
export interface ShadowAiCandidatesResponse {
  candidates: ShadowAiCandidate[];
  disclaimer: string;
}
