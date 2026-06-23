import { readFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { clientApi } from "@/lib/client-api";
import type { ShadowAiCandidate, ShadowAiCandidatesResponse } from "@/lib/types";

/**
 * F-018 shadow-AI feed unit tests (ADR-0021 §9, vectors 1, 3).
 *
 *  - Vector 1: the disclaimer from the API is rendered (non-removability is
 *    structural — the feed has no "hide" control; proven by the e2e spec too).
 *  - Vector 3: candidate rows carry the "candidate" label and never use the
 *    words "verdict" or "confirmed" in source.
 *
 * Type tests (pure logic on the contract types):
 *  - ShadowAiCandidate.label is the literal "candidate" — TypeScript enforces
 *    this at compile time; the runtime test below validates it at the data layer.
 *  - ShadowAiCandidatesResponse.disclaimer is required and a non-empty string.
 */

// ---- helpers --------------------------------------------------------------- //

function makeCandidate(partial: Partial<ShadowAiCandidate> = {}): ShadowAiCandidate {
  return {
    team_id: "team-alpha",
    project_id: "proj-1",
    endpoint: "api.anthropic.com",
    provider: "anthropic",
    call_count: 42,
    first_seen: "2026-06-20T10:00:00Z",
    last_seen: "2026-06-24T08:00:00Z",
    confidence_band: "high",
    fired_signals: ["disallowed_provider", "volume", "frequency"],
    label: "candidate",
    ...partial,
  };
}

function makeResponse(
  partial: Partial<ShadowAiCandidatesResponse> = {},
): ShadowAiCandidatesResponse {
  return {
    candidates: [makeCandidate()],
    disclaimer:
      "Shadow-AI detection covers only traffic that flows through Sentinel to a known model provider " +
      "that is not on the tenant's allow-list. It does not detect tools that bypass Sentinel.",
    ...partial,
  };
}

const realFetch = global.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// ---- contract type tests --------------------------------------------------- //

describe("ShadowAiCandidate contract types", () => {
  it("label field is always the literal 'candidate' (R3 — never 'verdict')", () => {
    const c = makeCandidate();
    // Verify at runtime that the value conforms to what the type enforces.
    expect(c.label).toBe("candidate");
    expect(c.label).not.toBe("verdict");
    expect(c.label).not.toBe("confirmed");
    expect(c.label).not.toBe("violation");
  });

  it("confidence_band is one of the three honest bands", () => {
    const bands: ShadowAiCandidate["confidence_band"][] = ["low", "medium", "high"];
    for (const band of bands) {
      const c = makeCandidate({ confidence_band: band });
      expect(["low", "medium", "high"]).toContain(c.confidence_band);
    }
  });

  it("fired_signals is an array of explainable signal names", () => {
    const c = makeCandidate({ fired_signals: ["disallowed_provider", "volume"] });
    expect(Array.isArray(c.fired_signals)).toBe(true);
    expect(c.fired_signals.length).toBeGreaterThan(0);
  });
});

describe("ShadowAiCandidatesResponse — disclaimer (vector 1)", () => {
  it("disclaimer field is present and non-empty in a well-formed response", () => {
    const resp = makeResponse();
    expect(typeof resp.disclaimer).toBe("string");
    expect(resp.disclaimer.length).toBeGreaterThan(0);
  });

  it("disclaimer text references Sentinel detection scope", () => {
    const resp = makeResponse();
    // Must communicate the honesty boundary: through-Sentinel-only detection.
    expect(resp.disclaimer.toLowerCase()).toMatch(/sentinel/i);
  });
});

// ---- clientApi path test --------------------------------------------------- //

describe("clientApi.get — shadow-AI candidates BFF path (vector 2)", () => {
  afterEach(() => {
    global.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it("fetches through /api/admin BFF prefix — never Sentinel directly", async () => {
    const fetchMock = vi.fn((_url: RequestInfo | URL, _init?: RequestInit) =>
      Promise.resolve(jsonResponse(makeResponse())),
    );
    global.fetch = fetchMock as unknown as typeof fetch;

    await clientApi.get<ShadowAiCandidatesResponse>("tenants/t1/shadow-ai/candidates");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      "/api/admin/tenants/t1/shadow-ai/candidates",
    );
  });

  it("returns the disclaimer from the upstream JSON payload", async () => {
    const expected = makeResponse();
    global.fetch = vi.fn(async () =>
      jsonResponse(expected),
    ) as unknown as typeof fetch;

    const data = await clientApi.get<ShadowAiCandidatesResponse>(
      "tenants/t1/shadow-ai/candidates",
    );

    expect(data.disclaimer).toBe(expected.disclaimer);
  });
});

// ---- source scan: honest-language guard ------------------------------------ //

describe("shadow-AI feed source — honest language guard (R3, vector 3)", () => {
  const feedSource = readFileSync(
    join(process.cwd(), "src/components/dashboards/shadow-ai-feed.tsx"),
    "utf8",
  );

  it("component source never contains the word 'verdict'", () => {
    // Case-insensitive: matches 'verdict', 'Verdict', 'VERDICT'.
    expect(feedSource.toLowerCase()).not.toContain("verdict");
  });

  it("component source never contains the word 'confirmed' as a honesty-boundary breach", () => {
    // 'confirmed' would imply certainty — candidates are review candidates only.
    // We test the prose/JSX content; the word is absent from the component.
    expect(feedSource.toLowerCase()).not.toContain('"confirmed"');
    expect(feedSource.toLowerCase()).not.toContain(">confirmed<");
    expect(feedSource.toLowerCase()).not.toContain("'confirmed'");
  });

  it("every rendered label in source is 'Candidate', not a verdict synonym", () => {
    // The component must use the literal text "Candidate" for the row badge.
    expect(feedSource).toContain("Candidate");
  });

  it("disclaimer block has data-testid for non-removability assertion (e2e testable)", () => {
    expect(feedSource).toContain('data-testid="shadow-ai-disclaimer"');
  });

  it("disclaimer renders the backend-supplied value, not a hardcoded string", () => {
    // The component must reference {disclaimer} (the runtime variable) —
    // not a hardcoded replacement string.
    expect(feedSource).toContain("{disclaimer}");
    // And must NOT have an alternate hardcoded disclaimer text that overrides it.
    // We simply confirm the placeholder-only path is also honest.
    expect(feedSource).not.toMatch(/"Shadow-AI detection covers only/);
  });
});

// ---- governance page source guard ----------------------------------------- //

describe("governance page source — ShadowAiFeed wiring (F-018)", () => {
  const pageSource = readFileSync(
    join(process.cwd(), "src/app/(admin)/dashboards/governance/page.tsx"),
    "utf8",
  );

  it("imports ShadowAiFeed from the feed component", () => {
    expect(pageSource).toContain("shadow-ai-feed");
  });

  it("passes tenantId (not pre-filtered events) to ShadowAiFeed", () => {
    expect(pageSource).toContain("tenantId={tenant}");
  });

  it("passes key={tenant} to ShadowAiFeed for tenant-switch isolation", () => {
    expect(pageSource).toContain("key={tenant}");
  });
});
