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
