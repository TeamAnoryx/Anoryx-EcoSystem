import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import { formatCompactCount, formatMinorUnitsCompact } from "@/lib/money";
import type { ExecutiveSummaryView } from "@/lib/types";

import { StatTile } from "@/components/dashboards/stat-tile";

export const dynamic = "force-dynamic";

const PRESETS: Array<{ label: string; hours: number }> = [
  { label: "Last 24h", hours: 24 },
  { label: "Last 7d", hours: 24 * 7 },
  { label: "Last 30d", hours: 24 * 30 },
];

const HOUR_MS = 3_600_000;

interface Search {
  tenant_id?: string;
  start?: string;
  end?: string;
}

function presetHref(tenantId: string, hours: number): string {
  const end = new Date();
  const start = new Date(end.getTime() - hours * HOUR_MS);
  const qp = new URLSearchParams({
    tenant_id: tenantId,
    start: start.toISOString(),
    end: end.toISOString(),
  });
  return `/executive?${qp.toString()}`;
}

export default function ExecutivePage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Executive</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Top-level financial rollup across D-008 spend, D-011 budget forecasts, and
          D-013 CRM pipeline for one tenant. Composes each module&apos;s own
          already-computed figures — this page derives nothing new (ADR-0020 §2). All
          cost figures are client-side cost estimates, not an authoritative bill.
        </p>
      </div>

      <form
        method="GET"
        className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-bg-raised p-4"
      >
        <div className="min-w-[16rem] flex-1">
          <label htmlFor="tenant_id" className="block text-sm font-medium text-fg">
            Tenant UUID
          </label>
          <input
            id="tenant_id"
            name="tenant_id"
            type="text"
            required
            defaultValue={tenantId ?? ""}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg"
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </div>
        <div>
          <label htmlFor="start" className="block text-sm font-medium text-fg">
            Start (UTC)
          </label>
          <input
            id="start"
            name="start"
            type="text"
            defaultValue={searchParams.start ?? ""}
            className="mt-1 w-56 rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-xs text-fg"
            placeholder="2026-07-01T00:00:00Z"
          />
        </div>
        <div>
          <label htmlFor="end" className="block text-sm font-medium text-fg">
            End (UTC)
          </label>
          <input
            id="end"
            name="end"
            type="text"
            defaultValue={searchParams.end ?? ""}
            className="mt-1 w-56 rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-xs text-fg"
            placeholder="2026-07-08T00:00:00Z"
          />
        </div>
        <button
          type="submit"
          className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg"
        >
          Load
        </button>
      </form>

      {tenantId ? (
        <div className="flex flex-wrap gap-2">
          {PRESETS.map((p) => (
            <a
              key={p.label}
              href={presetHref(tenantId, p.hours)}
              className="rounded-md border border-border px-3 py-1.5 text-xs text-fg-muted hover:border-accent hover:text-fg"
            >
              {p.label}
            </a>
          ))}
        </div>
      ) : null}

      {!tenantId ? (
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view its summary.</p>
      ) : !searchParams.start || !searchParams.end ? (
        <p className="text-sm text-fg-faint">
          Pick a window above (a preset, or type Start/End) to load data.
        </p>
      ) : (
        <ExecutiveSummaryForWindow
          tenantId={tenantId}
          start={searchParams.start}
          end={searchParams.end}
        />
      )}
    </div>
  );
}

async function ExecutiveSummaryForWindow({
  tenantId,
  start,
  end,
}: {
  tenantId: string;
  start: string;
  end: string;
}) {
  const currency = "USD"; // Delta is single-currency per tenant today (ADR-0001 Fork 4).

  let summary: ExecutiveSummaryView | null = null;
  let loadError: string | null = null;
  try {
    summary = await adminApi.getExecutiveSummary(tenantId, start, end);
  } catch (err) {
    loadError =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load summary.";
  }

  if (loadError) {
    return (
      <p role="alert" className="text-sm text-danger">
        {loadError}
      </p>
    );
  }

  return (
    <div className="space-y-6">
      <section className="space-y-3">
        <h2 className="text-sm font-medium text-fg">Spend (D-008)</h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatTile
            label="Total spend"
            value={formatMinorUnitsCompact(summary!.total_cost_cents, currency)}
          />
          <StatTile label="Requests" value={formatCompactCount(summary!.request_count)} />
          <StatTile
            label="Burn rate"
            value={`${formatMinorUnitsCompact(Math.round(summary!.burn_rate_cents_per_hour), currency)}/hr`}
          />
          <StatTile
            label="Generated at"
            value={new Date(summary!.generated_at).toLocaleString()}
          />
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-medium text-fg">Budget forecasts (D-011)</h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatTile label="Budgets" value={formatCompactCount(summary!.budget_count)} />
          <StatTile
            label="Current-period spend"
            value={formatMinorUnitsCompact(summary!.total_current_period_spend_cents, currency)}
          />
          <StatTile
            label="Projected period-end spend"
            value={
              summary!.total_projected_period_end_spend_cents === null
                ? "—"
                : formatMinorUnitsCompact(
                    Math.round(summary!.total_projected_period_end_spend_cents),
                    currency,
                  )
            }
            hint={
              summary!.total_projected_period_end_spend_cents === null
                ? "insufficient data to project"
                : undefined
            }
          />
          <StatTile
            label="At critical / warning"
            value={`${summary!.budgets_at_critical} / ${summary!.budgets_at_warning}`}
            hint={
              summary!.budgets_insufficient_data > 0
                ? `${summary!.budgets_insufficient_data} insufficient data`
                : undefined
            }
          />
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-medium text-fg">Pipeline (D-013)</h2>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatTile label="Clients" value={formatCompactCount(summary!.client_count)} />
          <StatTile label="Open deals" value={formatCompactCount(summary!.open_deal_count)} />
          <StatTile
            label="Open pipeline value"
            value={formatMinorUnitsCompact(
              summary!.open_pipeline_value_minor_units,
              summary!.pipeline_currency,
            )}
          />
        </div>
      </section>
    </div>
  );
}
