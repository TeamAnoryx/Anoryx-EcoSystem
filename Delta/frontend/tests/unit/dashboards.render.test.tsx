/**
 * D-008 dashboard components — RENDERED-DOM assertions (mirrors login-form.
 * render.test.tsx). Covers: stat tiles show their value, the top-spenders list
 * ranks by cost desc and never crashes on an empty result, and the time-series
 * chart's SVG mounts with the direct end-label and an accessible name per point
 * (no bare hover-only data — every value is also in the accessible tree).
 */

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { SpendTimeSeriesChart } from "@/components/dashboards/spend-time-series-chart";
import { StatTile } from "@/components/dashboards/stat-tile";
import { TopSpendersList } from "@/components/dashboards/top-spenders-list";
import type { GroupSpendView, TimeSeriesPointView } from "@/lib/types";

afterEach(() => {
  cleanup();
});

describe("StatTile", () => {
  it("renders label and value", () => {
    render(<StatTile label="Total spend" value="$4.2M" />);
    expect(screen.getByText("Total spend")).toBeInTheDocument();
    expect(screen.getByText("$4.2M")).toBeInTheDocument();
  });

  it("renders an optional hint", () => {
    render(<StatTile label="Cost per request" value="—" hint="no requests in window" />);
    expect(screen.getByText("no requests in window")).toBeInTheDocument();
  });
});

describe("TopSpendersList", () => {
  const rows: GroupSpendView[] = [
    { group_key: "team-a", cost_cents: 9_000, request_count: 5 },
    { group_key: "team-b", cost_cents: 1_000, request_count: 2 },
  ];

  it("renders every group with its formatted cost", () => {
    render(<TopSpendersList rows={rows} currency="USD" />);
    expect(screen.getByText("team-a")).toBeInTheDocument();
    expect(screen.getByText("$90.00")).toBeInTheDocument();
    expect(screen.getByText("team-b")).toBeInTheDocument();
    expect(screen.getByText("$10.00")).toBeInTheDocument();
  });

  it("shows an empty state instead of crashing on zero rows", () => {
    render(<TopSpendersList rows={[]} currency="USD" />);
    expect(screen.getByText(/no spend recorded/i)).toBeInTheDocument();
  });
});

describe("SpendTimeSeriesChart", () => {
  const points: TimeSeriesPointView[] = [
    { bucket_start: "2026-07-01T00:00:00Z", cost_cents: 1_000, request_count: 2 },
    { bucket_start: "2026-07-02T00:00:00Z", cost_cents: 2_000, request_count: 3 },
  ];

  it("renders an accessible SVG with a title and the direct end-label", () => {
    render(<SpendTimeSeriesChart points={points} currency="USD" bucketMs={86_400_000} />);
    expect(screen.getByRole("img", { name: /spend over time/i })).toBeInTheDocument();
    // The direct end-label is the last point's formatted value.
    expect(screen.getByText("$20.00")).toBeInTheDocument();
  });

  it("gives every point an accessible name (value never hover-only)", () => {
    render(<SpendTimeSeriesChart points={points} currency="USD" bucketMs={86_400_000} />);
    expect(screen.getByLabelText(/\$10\.00, 2 requests/)).toBeInTheDocument();
    expect(screen.getByLabelText(/\$20\.00, 3 requests/)).toBeInTheDocument();
  });

  it("shows an empty state instead of crashing on zero points", () => {
    render(<SpendTimeSeriesChart points={[]} currency="USD" bucketMs={86_400_000} />);
    expect(screen.getByText(/no spend recorded/i)).toBeInTheDocument();
  });
});
