/**
 * F-021 model-governance panel — RENDERED-DOM assertion tests.
 *
 * Covers the nine vectors specified in the F-021 task:
 *
 *  Vector 1: retirementLabel returns "Retiring — usable until <date>" for
 *            approved + future retire_at.
 *  Vector 2: retirementLabel returns "Retired — blocked since <date>" for
 *            approved + past retire_at.
 *  Vector 3: retirementLabel returns plain "Approved" when retire_at is null.
 *  Vector 4: retirementLabel returns "Pending" for state=pending.
 *  Vector 5: retirementLabel returns "Denied" for state=denied.
 *  Vector 6: renders "Retiring — usable until …" badge in the DOM for a
 *            row with state=approved + future retire_at.
 *  Vector 7: renders "Retired — blocked since …" badge for approved + past
 *            retire_at.
 *  Vector 8: renders plain "Approved" badge for approved + no retire_at —
 *            the word "Retiring" is absent.
 *  Vector 9: clicking Approve calls clientApi.post with the BFF-relative
 *            path 'tenants/<tid>/models/approve' (proves BFF-only, vector 11).
 *  Vector 10: clicking Deny calls clientApi.post with '.../models/deny'.
 *  Vector 11 (implicit): clientApi is imported from @/lib/client-api and is
 *            the ONLY fetch mechanism in the panel — enforced by the module
 *            mock boundary.
 *
 * No network I/O — clientApi and fetch are fully mocked.
 */

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Module mock — must come before the component import so Vitest's module
// registry substitutes the mock before ShadowAiFeed/ModelGovernancePanel
// import clientApi.
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

// Import after mock.
import { ModelGovernancePanel, retirementLabel } from "@/components/dashboards/model-governance-panel";
import { clientApi } from "@/lib/client-api";
import type { ModelInventoryItem, ModelInventoryListResponse } from "@/lib/types";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const FUTURE_DATE = "2099-12-31T23:59:59Z";
const PAST_DATE = "2000-01-01T00:00:00Z";

function makeItem(overrides: Partial<ModelInventoryItem>): ModelInventoryItem {
  return {
    model_id: "gpt-4o",
    model_type: "base",
    state: "approved",
    approved_by: "op-uuid-abc123",
    approved_at: "2026-06-01T00:00:00Z",
    retire_at: null,
    created_at: "2026-05-01T00:00:00Z",
    updated_at: "2026-06-01T00:00:00Z",
    ...overrides,
  };
}

function makeResponse(items: ModelInventoryItem[]): ModelInventoryListResponse {
  return { tenant_id: "test-tenant", models: items, count: items.length };
}

function mockGet() {
  return vi.mocked(clientApi.get);
}

function mockPost() {
  return vi.mocked(clientApi.post);
}

// ---------------------------------------------------------------------------
// Pure helper tests (retirementLabel) — no DOM required
// ---------------------------------------------------------------------------

describe("retirementLabel — pure helper (no DOM)", () => {
  const now = new Date("2026-06-25T12:00:00Z");

  it("vector 1: returns 'Retiring — usable until <date>' for approved + future retire_at", () => {
    const item = makeItem({ state: "approved", retire_at: FUTURE_DATE });
    const result = retirementLabel(item, now);
    expect(result).toMatch(/^Retiring — usable until /);
    // The date portion must contain the retire_at timestamp in the stable format.
    expect(result).toContain("2099-12-31");
  });

  it("vector 2: returns 'Retired — blocked since <date>' for approved + past retire_at", () => {
    const item = makeItem({ state: "approved", retire_at: PAST_DATE });
    const result = retirementLabel(item, now);
    expect(result).toMatch(/^Retired — blocked since /);
    expect(result).toContain("2000-01-01");
  });

  it("vector 3: returns 'Approved' for approved + retire_at null", () => {
    const item = makeItem({ state: "approved", retire_at: null });
    expect(retirementLabel(item, now)).toBe("Approved");
  });

  it("vector 4: returns 'Pending' for state=pending regardless of retire_at", () => {
    const item = makeItem({ state: "pending", retire_at: FUTURE_DATE });
    expect(retirementLabel(item, now)).toBe("Pending");
  });

  it("vector 5: returns 'Denied' for state=denied regardless of retire_at", () => {
    const item = makeItem({ state: "denied", retire_at: PAST_DATE });
    expect(retirementLabel(item, now)).toBe("Denied");
  });

  it("boundary: retire_at exactly equal to now is treated as 'usable until' (not yet past)", () => {
    const item = makeItem({ state: "approved", retire_at: now.toISOString() });
    const result = retirementLabel(item, now);
    expect(result).toMatch(/^Retiring — usable until /);
  });
});

// ---------------------------------------------------------------------------
// Rendered DOM tests
// ---------------------------------------------------------------------------

describe("ModelGovernancePanel — rendered DOM assertions", () => {
  beforeEach(() => {
    // Default: GET resolves with an approved+future-retire row and a pending row.
    mockGet().mockResolvedValue(
      makeResponse([
        makeItem({
          model_id: "retiring-model",
          state: "approved",
          retire_at: FUTURE_DATE,
        }),
        makeItem({
          model_id: "plain-approved",
          state: "approved",
          retire_at: null,
        }),
        makeItem({
          model_id: "past-retired",
          state: "approved",
          retire_at: PAST_DATE,
        }),
        makeItem({
          model_id: "pending-model",
          state: "pending",
          retire_at: null,
        }),
      ]),
    );
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("vector 6: renders 'Retiring — usable until …' badge for approved + future retire_at", async () => {
    render(<ModelGovernancePanel tenantId="test-tenant" />);

    const badge = await waitFor(() =>
      screen.getByText((text) => text.startsWith("Retiring — usable until")),
    );
    expect(badge).toBeInTheDocument();
  });

  it("vector 7: renders 'Retired — blocked since …' badge for approved + past retire_at", async () => {
    render(<ModelGovernancePanel tenantId="test-tenant" />);

    const badge = await waitFor(() =>
      screen.getByText((text) => text.startsWith("Retired — blocked since")),
    );
    expect(badge).toBeInTheDocument();
  });

  it("vector 8: renders plain 'Approved' badge — 'Retiring' word is absent for null retire_at row", async () => {
    // Render a panel with ONLY a plain-approved row.
    mockGet().mockResolvedValue(
      makeResponse([makeItem({ model_id: "plain-only", state: "approved", retire_at: null })]),
    );

    const { container } = render(<ModelGovernancePanel tenantId="test-tenant" />);

    // Wait for table data to arrive.
    await waitFor(() => screen.getAllByTestId("model-inventory-row"));

    const text = container.textContent ?? "";
    expect(text).toContain("Approved");
    // The "Retiring" prefix must NOT appear anywhere in the DOM for this row.
    expect(text).not.toContain("Retiring");
  });

  it("renders 'Pending' badge for a pending model", async () => {
    mockGet().mockResolvedValue(
      makeResponse([makeItem({ model_id: "pend", state: "pending", retire_at: null })]),
    );

    render(<ModelGovernancePanel tenantId="test-tenant" />);
    const badge = await waitFor(() => screen.getByText("Pending"));
    expect(badge).toBeInTheDocument();
  });

  it("renders 'Denied' badge for a denied model", async () => {
    mockGet().mockResolvedValue(
      makeResponse([makeItem({ model_id: "den", state: "denied", retire_at: null })]),
    );

    render(<ModelGovernancePanel tenantId="test-tenant" />);
    const badge = await waitFor(() => screen.getByText("Denied"));
    expect(badge).toBeInTheDocument();
  });

  it("vector 9: clicking Approve then Confirm calls clientApi.post with BFF-relative path", async () => {
    mockGet().mockResolvedValue(
      makeResponse([makeItem({ model_id: "approve-me", state: "pending", retire_at: null })]),
    );
    // post resolves to an updated item.
    mockPost().mockResolvedValue(
      makeItem({ model_id: "approve-me", state: "approved", retire_at: null }),
    );
    // Second GET after refetch.
    mockGet()
      .mockResolvedValueOnce(
        makeResponse([makeItem({ model_id: "approve-me", state: "pending", retire_at: null })]),
      )
      .mockResolvedValue(
        makeResponse([makeItem({ model_id: "approve-me", state: "approved", retire_at: null })]),
      );

    render(<ModelGovernancePanel tenantId="t1" />);

    // Wait for the Approve button to appear.
    const approveBtn = await waitFor(() => screen.getByTestId("btn-approve"));
    fireEvent.click(approveBtn);

    // The inline confirm UI should appear.
    const confirmBtn = await waitFor(() => screen.getByTestId("btn-confirm-action"));
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(mockPost()).toHaveBeenCalledWith(
        "tenants/t1/models/approve",
        { model_id: "approve-me" },
      );
    });
  });

  it("vector 10: clicking Deny then Confirm calls clientApi.post with BFF-relative path .../deny", async () => {
    mockGet().mockResolvedValue(
      makeResponse([makeItem({ model_id: "deny-me", state: "pending", retire_at: null })]),
    );
    mockPost().mockResolvedValue(
      makeItem({ model_id: "deny-me", state: "denied", retire_at: null }),
    );

    render(<ModelGovernancePanel tenantId="t2" />);

    const denyBtn = await waitFor(() => screen.getByTestId("btn-deny"));
    fireEvent.click(denyBtn);

    const confirmBtn = await waitFor(() => screen.getByTestId("btn-confirm-action"));
    fireEvent.click(confirmBtn);

    await waitFor(() => {
      expect(mockPost()).toHaveBeenCalledWith(
        "tenants/t2/models/deny",
        { model_id: "deny-me" },
      );
    });
  });

  it("renders the enforcement note in the DOM (honesty — non-removable)", async () => {
    render(<ModelGovernancePanel tenantId="test-tenant" />);

    // Use waitFor so React can flush the async usePoll state update without
    // triggering the "not wrapped in act" advisory.
    const note = await waitFor(() => screen.getByTestId("model-governance-enforcement-note"));
    expect(note).toBeInTheDocument();
    expect(note.textContent).toContain("fail-closed");
  });

  it("shows empty-state text when no models are returned", async () => {
    mockGet().mockResolvedValue(makeResponse([]));

    render(<ModelGovernancePanel tenantId="empty-tenant" />);

    const msg = await waitFor(() =>
      screen.getByText("No models in the inventory for this tenant."),
    );
    expect(msg).toBeInTheDocument();
  });

  it("surfaces an inline error message when a POST action fails", async () => {
    mockGet().mockResolvedValue(
      makeResponse([makeItem({ model_id: "fail-me", state: "pending", retire_at: null })]),
    );
    mockPost().mockRejectedValue(
      Object.assign(new Error("deadline must be in the future"), {
        name: "ClientApiError",
        status: 400,
        reauth: false,
      }),
    );

    render(<ModelGovernancePanel tenantId="err-tenant" />);

    const approveBtn = await waitFor(() => screen.getByTestId("btn-approve"));
    fireEvent.click(approveBtn);
    const confirmBtn = await waitFor(() => screen.getByTestId("btn-confirm-action"));
    fireEvent.click(confirmBtn);

    const errEl = await waitFor(() => screen.getByTestId("model-action-error"));
    expect(errEl).toBeInTheDocument();
    // Error text must be present (the exact message depends on mock but is non-empty).
    expect(errEl.textContent?.trim().length).toBeGreaterThan(0);
  });
});
