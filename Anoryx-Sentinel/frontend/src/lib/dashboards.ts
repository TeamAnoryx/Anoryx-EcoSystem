/**
 * Pure dashboard logic for F-013 (ADR-0016). No I/O, no `server-only`, no env —
 * everything here is deterministic and unit-tested under the node vitest lane.
 * Server-side fetch orchestration lives in `dashboards-server.ts`; client-side
 * polling uses `clientApi.get`. Keeping this module pure is what lets the threat
 * vectors (aggregation, poll gating, honest rendering) be tested in CI.
 */

import type { AuditEventResponse, OperatorEvidenceResponse } from "@/lib/types";

// --- Event-type allow-lists ------------------------------------------------ //

/**
 * Audit event types treated as "security-relevant" for the Security feed. These
 * are the event_type strings persisted to events_audit_log by the gateway
 * defense / policy / rate-limit paths (contracts/events.schema.json). The audit
 * projection is metadata-only, so the feed shows occurrence + action + scope,
 * never payload detail (ADR-0016 §1).
 */
export const SECURITY_EVENT_TYPES: ReadonlySet<string> = new Set([
  "injection_detected",
  "prompt_injection_detected_ml",
  "recursive_injection_attempt",
  "pii_blocked",
  "secret_leaked",
  "policy_violated",
  "policy_decision_deny",
  "shadow_ai_detected",
  "shadow_ai_detected_outbound",
  "rate_limit_degraded",
  "rate_limit_redis_error",
]);

/** Shadow-AI egress event types for the Governance feed (detect-only, progressive). */
export const SHADOW_AI_EVENT_TYPES: ReadonlySet<string> = new Set([
  "shadow_ai_detected_outbound",
  "shadow_ai_detected",
]);

/**
 * Known upstream providers (contracts/events.schema.json selected_provider enum).
 * The full per-tenant model inventory is NOT exposed by the admin API; the
 * Governance dashboard shows this static provider set + the tenant's configured
 * classifier as the honest partial (ADR-0016 deferral 2d).
 */
export const PROVIDERS: readonly string[] = ["openai", "anthropic", "bedrock"];

export function isSecurityEvent(event: AuditEventResponse): boolean {
  return SECURITY_EVENT_TYPES.has(event.event_type);
}

export function filterSecurityEvents(events: AuditEventResponse[]): AuditEventResponse[] {
  return events.filter(isSecurityEvent);
}

export function isShadowAiEvent(event: AuditEventResponse): boolean {
  return SHADOW_AI_EVENT_TYPES.has(event.event_type);
}

export function filterShadowAiEvents(events: AuditEventResponse[]): AuditEventResponse[] {
  return events.filter(isShadowAiEvent);
}

// --- Aggregation (Fork 3: client-side audit-log aggregate) ----------------- //

export interface CountBucket {
  key: string;
  count: number;
}

function aggregate(events: AuditEventResponse[], pick: (e: AuditEventResponse) => string): CountBucket[] {
  const counts = new Map<string, number>();
  for (const e of events) {
    const k = pick(e);
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  // Deterministic order: count desc, then key asc.
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}

/** Per-team counts over the supplied events (windowed to what is loaded). */
export function aggregateByTeam(events: AuditEventResponse[]): CountBucket[] {
  return aggregate(events, (e) => e.team_id);
}

/** Per-event-type counts over the supplied events. */
export function aggregateByType(events: AuditEventResponse[]): CountBucket[] {
  return aggregate(events, (e) => e.event_type);
}

// --- Polling gate (R7, threat vector 7) ------------------------------------ //

/**
 * Decide whether a poll tick should issue a request. Skips when the tab is
 * hidden (no background polling) or a prior request is still in-flight (no
 * request stacking). Pure so the polling discipline is unit-testable.
 */
export function shouldPollTick(hidden: boolean, inFlight: boolean): boolean {
  return !hidden && !inFlight;
}

// --- Time windows ---------------------------------------------------------- //

export type WindowKey = "1h" | "24h" | "7d";

export const TIME_WINDOWS: ReadonlyArray<{ key: WindowKey; label: string; ms: number }> = [
  { key: "1h", label: "Last 1h", ms: 60 * 60 * 1000 },
  { key: "24h", label: "Last 24h", ms: 24 * 60 * 60 * 1000 },
  { key: "7d", label: "Last 7d", ms: 7 * 24 * 60 * 60 * 1000 },
];

export const DEFAULT_WINDOW: WindowKey = "24h";

export function isWindowKey(value: string | undefined): value is WindowKey {
  return value === "1h" || value === "24h" || value === "7d";
}

/**
 * Resolve a window key + a caller-supplied "now" (ms epoch) to RFC3339 UTC
 * bounds [t0, t1). `now` is passed in (never read from the clock here) so this
 * stays pure and testable; the compliance server page supplies Date.now().
 */
export function windowRange(windowKey: WindowKey, nowMs: number): { t0: string; t1: string } {
  const win = TIME_WINDOWS.find((w) => w.key === windowKey) ?? TIME_WINDOWS[1];
  const t1 = new Date(nowMs);
  const t0 = new Date(nowMs - win.ms);
  return { t0: toRfc3339Z(t0), t1: toRfc3339Z(t1) };
}

/** RFC3339 UTC with a trailing 'Z' (the form the audit writers emit). */
function toRfc3339Z(d: Date): string {
  // Drop millis for a clean second-precision bound; the backend casts to timestamptz.
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

// --- Honest compliance rendering (R6 / F-011 R8) --------------------------- //

/** Mandatory honest framing — the UI must never imply certification. */
export const AUDIT_READY_LABEL = "Audit-ready — not a certification of compliance.";

export interface ReadinessView {
  framework: string;
  frameworkVersion: string;
  percent: string;
  passed: number;
  gap: number;
  notCovered: number;
  notApplicable: number;
  applicable: number;
  total: number;
  disclaimer: string;
}

/** Format a 0..1 readiness ratio as an integer percent string. */
export function readinessPercent(score: number): string {
  const clamped = Math.max(0, Math.min(1, score));
  return `${Math.round(clamped * 100)}%`;
}

/** Project the operator evidence response into the honest readiness view model. */
export function toReadinessView(ev: OperatorEvidenceResponse): ReadinessView {
  return {
    framework: ev.framework,
    frameworkVersion: ev.framework_version,
    percent: readinessPercent(ev.readiness_score),
    passed: ev.totals.passed,
    gap: ev.totals.gap,
    notCovered: ev.totals.not_covered,
    notApplicable: ev.totals.not_applicable,
    applicable: ev.totals.applicable,
    total: ev.totals.total,
    disclaimer: ev.disclaimer,
  };
}
