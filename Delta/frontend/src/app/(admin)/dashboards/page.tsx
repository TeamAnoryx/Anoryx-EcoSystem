import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import { formatCompactCount, formatMinorUnits, formatMinorUnitsCompact } from "@/lib/money";
import type { DashboardGroupDimension, GroupSpendView, SpendSummaryView, TimeSeriesPointView } from "@/lib/types";

import { SpendTimeSeriesChart } from "@/components/dashboards/spend-time-series-chart";
import { StatTile } from "@/components/dashboards/stat-tile";
import { TopSpendersList } from "@/components/dashboards/top-spenders-list";

export const dynamic = "force-dynamic";

const PRESETS: Array<{ label: string; hours: number }> = [
  { label: "Last 24h", hours: 24 },
  { label: "Last 7d", hours: 24 * 7 },
  { label: "Last 30d", hours: 24 * 30 },
];

const GROUP_OPTIONS: Array<{ label: string; value: DashboardGroupDimension }> = [
  { label: "Team", value: "team_id" },
  { label: "Project", value: "project_id" },
  { label: "Agent", value: "agent_id" },
];

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;

interface Search {
  tenant_id?: string;
  start?: string;
  end?: string;
  team_id?: string;
  project_id?: string;
  agent_id?: string;
  group_by?: string;
}

function presetHref(tenantId: string, hours: number, extra: Record<string, string | undefined>) {
  const end = new Date();
  const start = new Date(end.getTime() - hours * HOUR_MS);
  const qp = new URLSearchParams({
    tenant_id: tenantId,
    start: start.toISOString(),
    end: end.toISOString(),
  });
  for (const [k, v] of Object.entries(extra)) if (v) qp.set(k, v);
  return `/dashboards?${qp.toString()}`;
}

export default function DashboardsPage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Dashboards</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Real-time spend, burn rate, and top spenders over the D-003 ledger. Delta has no tenant
          directory UI yet — enter the tenant UUID below.
        </p>
      </div>

      <form method="GET" className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-bg-raised p-4">
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
        <div>
          <label htmlFor="team_id" className="block text-sm font-medium text-fg">
            Team (optional)
          </label>
          <input
            id="team_id"
            name="team_id"
            type="text"
            defaultValue={searchParams.team_id ?? ""}
            className="mt-1 w-40 rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-xs text-fg"
          />
        </div>
        <div>
          <label htmlFor="project_id" className="block text-sm font-medium text-fg">
            Project (optional)
          </label>
          <input
            id="project_id"
            name="project_id"
            type="text"
            defaultValue={searchParams.project_id ?? ""}
            className="mt-1 w-40 rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-xs text-fg"
          />
        </div>
        <div>
          <label htmlFor="agent_id" className="block text-sm font-medium text-fg">
            Agent (optional)
          </label>
          <input
            id="agent_id"
            name="agent_id"
            type="text"
            defaultValue={searchParams.agent_id ?? ""}
            className="mt-1 w-32 rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-xs text-fg"
          />
        </div>
        <button type="submit" className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg">
          Load
        </button>
      </form>

      {tenantId ? (
        <div className="flex flex-wrap gap-2">
          {PRESETS.map((p) => (
            <a
              key={p.label}
              href={presetHref(tenantId, p.hours, {
                team_id: searchParams.team_id,
                project_id: searchParams.project_id,
                agent_id: searchParams.agent_id,
              })}
              className="rounded-md border border-border px-3 py-1.5 text-xs text-fg-muted hover:border-accent hover:text-fg"
            >
              {p.label}
            </a>
          ))}
        </div>
      ) : null}

      {!tenantId ? (
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view its dashboards.</p>
      ) : !searchParams.start || !searchParams.end ? (
        <p className="text-sm text-fg-faint">Pick a window above (a preset, or type Start/End) to load data.</p>
      ) : (
        <DashboardsForWindow
          tenantId={tenantId}
          start={searchParams.start}
          end={searchParams.end}
          teamId={searchParams.team_id}
          projectId={searchParams.project_id}
          agentId={searchParams.agent_id}
          groupBy={resolveGroupBy(searchParams)}
        />
      )}
    </div>
  );
}

/**
 * group_by must never equal a dimension already pinned as a scope filter (the
 * backend rejects that combination as a no-op ranking — 422). Pick the
 * requested group_by if it's valid; otherwise the first dimension that isn't
 * pinned.
 */
function resolveGroupBy(searchParams: Search): DashboardGroupDimension {
  const pinned = new Set(
    (["team_id", "project_id", "agent_id"] as const).filter((k) => searchParams[k]),
  );
  const requested = searchParams.group_by as DashboardGroupDimension | undefined;
  if (requested && !pinned.has(requested)) return requested;
  return GROUP_OPTIONS.map((g) => g.value).find((v) => !pinned.has(v)) ?? "team_id";
}

async function DashboardsForWindow({
  tenantId,
  start,
  end,
  teamId,
  projectId,
  agentId,
  groupBy,
}: {
  tenantId: string;
  start: string;
  end: string;
  teamId?: string;
  projectId?: string;
  agentId?: string;
  groupBy: DashboardGroupDimension;
}) {
  const scope = { team_id: teamId, project_id: projectId, agent_id: agentId };
  const currency = "USD"; // Delta is single-currency per tenant today (ADR-0001 Fork 4).

  let summary: SpendSummaryView | null = null;
  let series: TimeSeriesPointView[] = [];
  let top: GroupSpendView[] = [];
  let loadError: string | null = null;

  try {
    [summary, series, top] = await Promise.all([
      adminApi.getSummary(tenantId, start, end, scope),
      adminApi.getTimeSeries(tenantId, start, end, "day", scope),
      adminApi.getTopSpenders(tenantId, start, end, groupBy, 10, scope),
    ]);
  } catch (err) {
    loadError = err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load dashboards.";
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
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatTile label="Total spend" value={formatMinorUnitsCompact(summary!.total_cost_cents, currency)} />
        <StatTile label="Requests" value={formatCompactCount(summary!.request_count)} />
        <StatTile
          label="Cost per request"
          value={
            summary!.cost_per_request_cents === null
              ? "—"
              : formatMinorUnits(Math.round(summary!.cost_per_request_cents), currency)
          }
          hint={summary!.request_count === 0 ? "no requests in window" : undefined}
        />
        <StatTile
          label="Burn rate"
          value={`${formatMinorUnits(Math.round(summary!.burn_rate_cents_per_hour), currency)}/hr`}
        />
      </div>

      <section className="rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="mb-3 text-sm font-medium text-fg">Spend over time</h2>
        <SpendTimeSeriesChart points={series} currency={currency} bucketMs={DAY_MS} />
      </section>

      <section className="rounded-lg border border-border bg-bg-raised p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 className="text-sm font-medium text-fg">Top spenders</h2>
          <div className="flex gap-1">
            {/* A dimension already pinned as a scope filter is omitted here — the
                backend rejects group_by == a pinned scope filter as a no-op
                ranking (422); see resolveGroupBy above. */}
            {GROUP_OPTIONS.filter(
              (g) =>
                !(
                  (g.value === "team_id" && teamId) ||
                  (g.value === "project_id" && projectId) ||
                  (g.value === "agent_id" && agentId)
                ),
            ).map((g) => (
              <a
                key={g.value}
                href={presetGroupHref({ tenantId, start, end, teamId, projectId, agentId, groupBy: g.value })}
                className={`rounded-md px-2 py-1 text-xs ${
                  groupBy === g.value ? "bg-bg-inset font-medium text-fg" : "text-fg-muted hover:text-fg"
                }`}
              >
                {g.label}
              </a>
            ))}
          </div>
        </div>
        <TopSpendersList rows={top} currency={currency} />
      </section>

      {/* Table view (dataviz skill accessibility check #6): every value the
          chart shows is also reachable as a plain table, no hover required. */}
      <section className="rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="mb-3 text-sm font-medium text-fg">Spend by day (table view)</h2>
        {series.length === 0 ? (
          <p className="text-sm text-fg-faint">No spend recorded in this window.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Day</th>
                  <th className="py-1 pr-4 font-medium">Spend</th>
                  <th className="py-1 font-medium">Requests</th>
                </tr>
              </thead>
              <tbody>
                {series.map((p) => (
                  <tr key={p.bucket_start} className="border-t border-border">
                    <td className="py-1 pr-4 font-mono text-xs text-fg-muted">
                      {new Date(p.bucket_start).toLocaleDateString()}
                    </td>
                    <td className="py-1 pr-4 tabular-nums text-fg">{formatMinorUnits(p.cost_cents, currency)}</td>
                    <td className="py-1 tabular-nums text-fg-muted">{p.request_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function presetGroupHref(args: {
  tenantId: string;
  start: string;
  end: string;
  teamId?: string;
  projectId?: string;
  agentId?: string;
  groupBy: DashboardGroupDimension;
}) {
  const qp = new URLSearchParams({
    tenant_id: args.tenantId,
    start: args.start,
    end: args.end,
    group_by: args.groupBy,
  });
  if (args.teamId) qp.set("team_id", args.teamId);
  if (args.projectId) qp.set("project_id", args.projectId);
  if (args.agentId) qp.set("agent_id", args.agentId);
  return `/dashboards?${qp.toString()}`;
}
