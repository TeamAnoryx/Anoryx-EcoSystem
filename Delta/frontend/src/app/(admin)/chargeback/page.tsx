import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import { formatMinorUnits, formatMinorUnitsCompact } from "@/lib/money";
import type { AnomalyReportView, ChargebackReportView, DashboardGroupDimension } from "@/lib/types";

import { StatTile } from "@/components/dashboards/stat-tile";

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

interface Search {
  tenant_id?: string;
  start?: string;
  end?: string;
  team_id?: string;
  project_id?: string;
  agent_id?: string;
  group_by?: string;
  baseline_periods?: string;
}

const VALID_GROUP_DIMENSIONS: readonly DashboardGroupDimension[] = ["team_id", "project_id", "agent_id"];

/**
 * Mirrors dashboards/page.tsx's resolveGroupBy exactly (same 422 the backend would
 * otherwise return for group_by == a pinned scope filter — independent security
 * review precedent, docs/audit/d-008-security-audit.md finding #3).
 */
function resolveGroupBy(searchParams: Search): DashboardGroupDimension {
  const pinned = new Set(
    (["team_id", "project_id", "agent_id"] as const).filter((k) => searchParams[k]),
  );
  const requested = VALID_GROUP_DIMENSIONS.includes(searchParams.group_by as DashboardGroupDimension)
    ? (searchParams.group_by as DashboardGroupDimension)
    : undefined;
  if (requested && !pinned.has(requested)) return requested;
  return GROUP_OPTIONS.map((g) => g.value).find((v) => !pinned.has(v)) ?? "team_id";
}

function resolveBaselinePeriods(searchParams: Search): number {
  const n = Number(searchParams.baseline_periods);
  if (!Number.isFinite(n) || n < 1 || n > 90) return 7;
  return Math.floor(n);
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
  return `/chargeback?${qp.toString()}`;
}

export default function ChargebackPage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Chargeback / Showback</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Departmental cost-attribution report + trailing-average spend-spike detection over the
          D-003 ledger. Informational only — the same client-side cost estimates the rest of Delta
          already is, never an authoritative bill or invoice.
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
          <label htmlFor="baseline_periods" className="block text-sm font-medium text-fg">
            Baseline periods
          </label>
          <input
            id="baseline_periods"
            name="baseline_periods"
            type="number"
            min={1}
            max={90}
            defaultValue={searchParams.baseline_periods ?? "7"}
            className="mt-1 w-24 rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-xs text-fg"
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
                baseline_periods: searchParams.baseline_periods,
              })}
              className="rounded-md border border-border px-3 py-1.5 text-xs text-fg-muted hover:border-accent hover:text-fg"
            >
              {p.label}
            </a>
          ))}
        </div>
      ) : null}

      {!tenantId ? (
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view its chargeback report.</p>
      ) : !searchParams.start || !searchParams.end ? (
        <p className="text-sm text-fg-faint">Pick a window above (a preset, or type Start/End) to load data.</p>
      ) : (
        <ChargebackForWindow
          tenantId={tenantId}
          start={searchParams.start}
          end={searchParams.end}
          teamId={searchParams.team_id}
          projectId={searchParams.project_id}
          agentId={searchParams.agent_id}
          groupBy={resolveGroupBy(searchParams)}
          baselinePeriods={resolveBaselinePeriods(searchParams)}
        />
      )}
    </div>
  );
}

async function ChargebackForWindow({
  tenantId,
  start,
  end,
  teamId,
  projectId,
  agentId,
  groupBy,
  baselinePeriods,
}: {
  tenantId: string;
  start: string;
  end: string;
  teamId?: string;
  projectId?: string;
  agentId?: string;
  groupBy: DashboardGroupDimension;
  baselinePeriods: number;
}) {
  const scope = { team_id: teamId, project_id: projectId, agent_id: agentId };
  const currency = "USD"; // Delta is single-currency per tenant today (ADR-0001 Fork 4).

  let report: ChargebackReportView | null = null;
  let anomalyReport: AnomalyReportView | null = null;
  let loadError: string | null = null;

  try {
    [report, anomalyReport] = await Promise.all([
      adminApi.getChargebackReport(tenantId, start, end, groupBy, scope),
      adminApi.getAnomalies(tenantId, start, end, groupBy, baselinePeriods, scope),
    ]);
  } catch (err) {
    loadError = err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load chargeback report.";
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
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <StatTile label="Total spend" value={formatMinorUnitsCompact(report!.total_cost_cents, currency)} />
        <StatTile label="Departments" value={String(report!.rows.length)} />
        <StatTile
          label="Anomalies flagged"
          value={String(anomalyReport!.anomalies.length)}
          hint={`vs. ${anomalyReport!.baseline_periods}-period trailing average`}
        />
      </div>

      <section className="rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="mb-3 text-sm font-medium text-fg">Chargeback / showback report</h2>
        {report!.rows.length === 0 ? (
          <p className="text-sm text-fg-faint">No spend recorded in this window.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">
                    {GROUP_OPTIONS.find((g) => g.value === groupBy)?.label ?? groupBy}
                  </th>
                  <th className="py-1 pr-4 font-medium">Spend</th>
                  <th className="py-1 pr-4 font-medium">Share</th>
                  <th className="py-1 font-medium">Requests</th>
                </tr>
              </thead>
              <tbody>
                {report!.rows.map((r) => (
                  <tr key={r.group_key} className="border-t border-border">
                    <td className="max-w-xs truncate py-1.5 pr-4 font-mono text-xs text-fg-muted" title={r.group_key}>
                      {r.group_key}
                    </td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg">{formatMinorUnits(r.cost_cents, currency)}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">{r.share_pct.toFixed(1)}%</td>
                    <td className="py-1.5 tabular-nums text-fg-muted">{r.request_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="rounded-lg border border-border bg-bg-raised p-4">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h2 className="text-sm font-medium text-fg">Anomalies</h2>
          <span className="font-mono text-xs text-fg-faint">method: {anomalyReport!.method}</span>
        </div>
        {anomalyReport!.anomalies.length === 0 ? (
          <p className="text-sm text-fg-faint">
            No spend spikes or new spenders detected against the {anomalyReport!.baseline_periods}-period
            trailing average.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">
                    {GROUP_OPTIONS.find((g) => g.value === groupBy)?.label ?? groupBy}
                  </th>
                  <th className="py-1 pr-4 font-medium">Current</th>
                  <th className="py-1 pr-4 font-medium">Baseline avg</th>
                  <th className="py-1 pr-4 font-medium">Ratio</th>
                  <th className="py-1 font-medium">Signal</th>
                </tr>
              </thead>
              <tbody>
                {anomalyReport!.anomalies.map((a) => (
                  <tr key={a.group_key} className="border-t border-border">
                    <td className="max-w-xs truncate py-1.5 pr-4 font-mono text-xs text-fg-muted" title={a.group_key}>
                      {a.group_key}
                    </td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg">
                      {formatMinorUnits(a.current_spend_cents, currency)}
                    </td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {formatMinorUnits(Math.round(a.baseline_avg_cents), currency)}
                    </td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {a.ratio === null ? "—" : `${a.ratio.toFixed(1)}x`}
                    </td>
                    <td className="py-1.5">
                      <span
                        className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                          a.severity === "warning" ? "bg-warn/15 text-warn" : "bg-bg-inset text-fg-muted"
                        }`}
                      >
                        {a.code === "SPEND_SPIKE" ? "Spend spike" : "New spender"}
                      </span>
                    </td>
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
