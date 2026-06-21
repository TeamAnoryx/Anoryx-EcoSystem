import { describe, expect, it } from "vitest";

import {
  AUDIT_READY_LABEL,
  aggregateByTeam,
  aggregateByType,
  filterSecurityEvents,
  filterShadowAiEvents,
  isWindowKey,
  readinessPercent,
  shouldPollTick,
  toReadinessView,
  windowRange,
} from "@/lib/dashboards";
import type { AuditEventResponse, OperatorEvidenceResponse } from "@/lib/types";

function ev(partial: Partial<AuditEventResponse>): AuditEventResponse {
  return {
    sequence_number: 1,
    event_id: "e1",
    event_type: "usage",
    event_timestamp: "2026-06-21T12:00:00Z",
    request_id: "r1",
    tenant_id: "t1",
    team_id: "team-a",
    project_id: "p1",
    agent_id: "gateway-core",
    action_taken: null,
    prev_hash: "0".repeat(64),
    row_hash: "1".repeat(64),
    ...partial,
  };
}

describe("security/shadow event filtering", () => {
  it("keeps security event types and drops non-security ones", () => {
    const events = [
      ev({ event_type: "injection_detected" }),
      ev({ event_type: "pii_blocked" }),
      ev({ event_type: "usage" }),
      ev({ event_type: "admin_audit_accessed" }),
      ev({ event_type: "shadow_ai_detected_outbound" }),
    ];
    const out = filterSecurityEvents(events).map((e) => e.event_type);
    expect(out).toEqual(["injection_detected", "pii_blocked", "shadow_ai_detected_outbound"]);
  });

  it("filters shadow-AI events only", () => {
    const events = [
      ev({ event_type: "shadow_ai_detected_outbound" }),
      ev({ event_type: "injection_detected" }),
      ev({ event_type: "shadow_ai_detected" }),
    ];
    const out = filterShadowAiEvents(events).map((e) => e.event_type);
    expect(out).toEqual(["shadow_ai_detected_outbound", "shadow_ai_detected"]);
  });
});

describe("aggregation (client-side, deterministic)", () => {
  it("counts by team, sorted count desc then key asc", () => {
    const events = [
      ev({ team_id: "team-b" }),
      ev({ team_id: "team-a" }),
      ev({ team_id: "team-a" }),
      ev({ team_id: "team-c" }),
    ];
    expect(aggregateByTeam(events)).toEqual([
      { key: "team-a", count: 2 },
      { key: "team-b", count: 1 },
      { key: "team-c", count: 1 },
    ]);
  });

  it("counts by event type", () => {
    const events = [
      ev({ event_type: "pii_blocked" }),
      ev({ event_type: "pii_blocked" }),
      ev({ event_type: "injection_detected" }),
    ];
    expect(aggregateByType(events)).toEqual([
      { key: "pii_blocked", count: 2 },
      { key: "injection_detected", count: 1 },
    ]);
  });

  it("returns empty for no events", () => {
    expect(aggregateByTeam([])).toEqual([]);
  });
});

describe("poll gate (R7, vector 7)", () => {
  it("ticks only when visible and not in-flight", () => {
    expect(shouldPollTick(false, false)).toBe(true);
    expect(shouldPollTick(true, false)).toBe(false); // hidden → pause
    expect(shouldPollTick(false, true)).toBe(false); // in-flight → no stacking
    expect(shouldPollTick(true, true)).toBe(false);
  });
});

describe("time windows", () => {
  it("validates window keys", () => {
    expect(isWindowKey("1h")).toBe(true);
    expect(isWindowKey("24h")).toBe(true);
    expect(isWindowKey("7d")).toBe(true);
    expect(isWindowKey("99d")).toBe(false);
    expect(isWindowKey(undefined)).toBe(false);
  });

  it("computes RFC3339 Z bounds from a fixed now", () => {
    const now = Date.UTC(2026, 5, 21, 12, 0, 0); // 2026-06-21T12:00:00Z
    expect(windowRange("24h", now)).toEqual({
      t0: "2026-06-20T12:00:00Z",
      t1: "2026-06-21T12:00:00Z",
    });
    expect(windowRange("1h", now).t0).toBe("2026-06-21T11:00:00Z");
    expect(windowRange("7d", now).t0).toBe("2026-06-14T12:00:00Z");
  });

  it("emits second-precision Z form the backend parser accepts", () => {
    const { t0, t1 } = windowRange("1h", Date.UTC(2026, 0, 1, 0, 30, 0));
    const re = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
    expect(t0).toMatch(re);
    expect(t1).toMatch(re);
  });
});

describe("honest compliance rendering (R6, vector 6)", () => {
  it("formats readiness percent and clamps", () => {
    expect(readinessPercent(0.7333)).toBe("73%");
    expect(readinessPercent(1)).toBe("100%");
    expect(readinessPercent(1.5)).toBe("100%");
    expect(readinessPercent(-0.1)).toBe("0%");
  });

  it("audit-ready label never claims compliance", () => {
    const label = AUDIT_READY_LABEL.toLowerCase();
    expect(label).toContain("audit-ready");
    expect(label).not.toContain("certified");
    // No affirmative "compliant" adjective ("compliance" in "...of compliance" is fine).
    expect(label).not.toContain("compliant");
  });

  it("projects evidence into the view, preserving gaps and disclaimer", () => {
    const ev0: OperatorEvidenceResponse = {
      tenant_id: "t1",
      framework: "SOC2",
      framework_version: "2017",
      window: { t0: "a", t1: "b" },
      readiness_score: 0.5,
      totals: {
        total: 10,
        passed: 4,
        gap: 3,
        not_applicable: 2,
        not_covered: 1,
        applicable: 8,
      },
      disclaimer: "Certification requires an accredited auditor.",
    };
    const view = toReadinessView(ev0);
    expect(view.percent).toBe("50%");
    expect(view.gap).toBe(3);
    expect(view.notCovered).toBe(1);
    expect(view.disclaimer).toContain("accredited auditor");
  });
});
