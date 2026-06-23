/**
 * F-018 shadow-AI feed — RENDERED-DOM assertion test (ADR-0021 §9, vector 1).
 *
 * Addresses the code-review gap: the R1 disclaimer and R3 candidate label
 * were only covered by SOURCE-SCAN unit tests. This test renders the actual
 * ShadowAiFeed component in a jsdom environment and asserts against the DOM
 * nodes that land in the browser.
 *
 * Covers:
 *  - Vector 1 (R1): disclaimer node is present and carries the backend text.
 *  - Vector 3 (R3): candidate row shows "Candidate" label and "high" band.
 *  - Negative guard: rendered HTML contains neither "verdict" nor "confirmed"
 *    as visible text.
 */

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Module mock — must come before the component import so Vitest's module
// registry sees the mock when ShadowAiFeed imports clientApi.
// ---------------------------------------------------------------------------
vi.mock("@/lib/client-api", () => ({
  clientApi: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
  },
  ClientApiError: class ClientApiError extends Error {
    readonly status: number;
    readonly reauth: boolean;
    constructor(status: number, message: string, reauth = false) {
      super(message);
      this.name = "ClientApiError";
      this.status = status;
      this.reauth = reauth;
    }
  },
}));

// Import after mock registration.
import { ShadowAiFeed } from "@/components/dashboards/shadow-ai-feed";
import { clientApi } from "@/lib/client-api";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const DISCLAIMER_TEXT =
  "DISCLAIMER-SENTINEL-MARKER does not detect tools that bypass Sentinel";

const MOCK_PAYLOAD = {
  candidates: [
    {
      team_id: "t",
      project_id: "p",
      endpoint: "api.anthropic.com/v1",
      provider: "anthropic",
      call_count: 7,
      first_seen: "2026-06-20T10:00:00Z",
      last_seen: "2026-06-24T08:00:00Z",
      confidence_band: "high" as const,
      fired_signals: ["disallowed_provider", "frequency", "volume"],
      label: "candidate" as const,
    },
  ],
  disclaimer: DISCLAIMER_TEXT,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Cast the mock so TypeScript lets us set per-test return values without
 * having to cast in every it() block.
 */
function mockGet() {
  return vi.mocked(clientApi.get);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ShadowAiFeed — rendered DOM assertions (ADR-0021 §9, vector 1)", () => {
  beforeEach(() => {
    // jsdom document.hidden is false by default → the first poll tick fires.
    // Mock the clientApi.get to resolve immediately with the known payload.
    mockGet().mockResolvedValue(MOCK_PAYLOAD);
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("renders the disclaimer node with non-empty text in the DOM (R1)", async () => {
    render(<ShadowAiFeed tenantId="tenant-test-1" />);

    const disclaimer = await waitFor(() => screen.getByTestId("shadow-ai-disclaimer"));

    // The node must be in the DOM.
    expect(disclaimer).toBeInTheDocument();

    // The text content must be non-empty.
    expect(disclaimer.textContent?.trim().length).toBeGreaterThan(0);
  });

  it("renders the backend-supplied disclaimer text verbatim (R1 non-removability)", async () => {
    render(<ShadowAiFeed tenantId="tenant-test-2" />);

    const disclaimer = await waitFor(() => {
      const el = screen.getByTestId("shadow-ai-disclaimer");
      // Wait until the real disclaimer text (not the loading placeholder) is in place.
      if (!el.textContent?.includes("DISCLAIMER-SENTINEL-MARKER")) {
        throw new Error("disclaimer not yet populated");
      }
      return el;
    });

    expect(disclaimer.textContent).toContain(DISCLAIMER_TEXT);
  });

  it("renders a candidate row with the label 'Candidate' (R3 — no verdict language)", async () => {
    render(<ShadowAiFeed tenantId="tenant-test-3" />);

    // Wait for at least one candidate row.
    await waitFor(() => screen.getAllByTestId("shadow-ai-candidate-row"));

    // The badge text must be "Candidate".
    const labelBadge = await screen.findByText("Candidate");
    expect(labelBadge).toBeInTheDocument();
  });

  it("renders the confidence band 'high' for the candidate row (R3)", async () => {
    render(<ShadowAiFeed tenantId="tenant-test-4" />);

    await waitFor(() => screen.getAllByTestId("shadow-ai-candidate-row"));

    const bandBadge = await screen.findByText("high");
    expect(bandBadge).toBeInTheDocument();
  });

  it("rendered HTML contains neither 'verdict' nor 'confirmed' as visible text (R3 negative guard)", async () => {
    const { container } = render(<ShadowAiFeed tenantId="tenant-test-5" />);

    // Wait for data to land.
    await waitFor(() => screen.getAllByTestId("shadow-ai-candidate-row"));

    const text = container.textContent ?? "";

    // "verdict" must not appear in any visible text node.
    expect(text.toLowerCase()).not.toContain("verdict");

    // "confirmed" (as a certainty claim) must not appear.
    // The word "confirmed" could appear as a confirmation UI element; we
    // assert it is absent because R3 prohibits certainty language.
    expect(text.toLowerCase()).not.toContain("confirmed");
  });

  it("renders exactly one candidate row for the single-candidate payload", async () => {
    render(<ShadowAiFeed tenantId="tenant-test-6" />);

    const rows = await waitFor(() => {
      const r = screen.getAllByTestId("shadow-ai-candidate-row");
      expect(r).toHaveLength(1);
      return r;
    });

    expect(rows).toHaveLength(1);
  });
});
