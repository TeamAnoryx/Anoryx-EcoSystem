import Link from "next/link";
import { notFound } from "next/navigation";

import { DecisionButtons } from "@/components/allocations/decision-buttons";
import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import { formatMinorUnits } from "@/lib/money";

export const dynamic = "force-dynamic";

export default async function AllocationDetailPage({
  params,
  searchParams,
}: {
  params: { id: string };
  searchParams: { tenant_id?: string };
}) {
  const tenantId = searchParams.tenant_id?.trim();

  if (!tenantId) {
    return (
      <div className="space-y-3">
        <h1 className="font-mono text-lg font-semibold text-fg">Allocation</h1>
        <p role="alert" className="text-sm text-danger">
          A <code>?tenant_id=</code> query parameter is required to look up this allocation.
        </p>
        <Link href="/allocations" className="text-sm text-accent hover:underline">
          Back to allocations
        </Link>
      </div>
    );
  }

  let allocation;
  try {
    allocation = await adminApi.getAllocation(tenantId, params.id);
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 404) {
      notFound();
    }
    throw err;
  }

  const isDecided = allocation.status !== "requested";

  return (
    <div className="space-y-6">
      <div>
        <Link href={`/allocations?tenant_id=${encodeURIComponent(tenantId)}`} className="text-sm text-accent hover:underline">
          ← Back to allocations
        </Link>
        <h1 className="mt-2 font-mono text-lg font-semibold text-fg">{allocation.allocation_id}</h1>
        <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
          <div>
            <dt className="text-fg-faint">Status</dt>
            <dd className="text-fg">{allocation.status}</dd>
          </div>
          <div>
            <dt className="text-fg-faint">Total</dt>
            <dd className="text-fg">{formatMinorUnits(allocation.total_minor_units, allocation.currency)}</dd>
          </div>
          <div>
            <dt className="text-fg-faint">Period</dt>
            <dd className="text-fg">{allocation.period}</dd>
          </div>
          <div>
            <dt className="text-fg-faint">Requested by</dt>
            <dd className="text-fg">{allocation.requested_by}</dd>
          </div>
          <div>
            <dt className="text-fg-faint">Requested at</dt>
            <dd className="text-fg">{allocation.requested_at}</dd>
          </div>
          <div>
            <dt className="text-fg-faint">Decided by</dt>
            <dd className="text-fg">{allocation.decided_by ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-fg-faint">Decided at</dt>
            <dd className="text-fg">{allocation.decided_at ?? "—"}</dd>
          </div>
        </dl>
      </div>

      <div>
        <h2 className="font-mono text-sm font-semibold text-fg">Targets</h2>
        <div className="mt-2 overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-raised text-fg-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Scope</th>
                <th className="px-3 py-2 font-medium">Team</th>
                <th className="px-3 py-2 font-medium">Project</th>
                <th className="px-3 py-2 font-medium">Agent</th>
                <th className="px-3 py-2 font-medium">Amount</th>
                <th className="px-3 py-2 font-medium">Budget id</th>
              </tr>
            </thead>
            <tbody>
              {allocation.targets.map((t, i) => (
                <tr key={i} className="border-t border-border">
                  <td className="px-3 py-2">{t.scope}</td>
                  <td className="px-3 py-2 font-mono text-xs">{t.team_id}</td>
                  <td className="px-3 py-2 font-mono text-xs">{t.project_id}</td>
                  <td className="px-3 py-2 font-mono text-xs">{t.agent_id}</td>
                  <td className="px-3 py-2">{formatMinorUnits(t.amount_minor_units, allocation.currency)}</td>
                  <td className="px-3 py-2 font-mono text-xs">{t.budget_id ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <DecisionButtons allocationId={allocation.allocation_id} tenantId={tenantId} disabled={isDecided} />

      {isDecided ? (
        <p className="text-sm text-fg-faint">
          This allocation was already {allocation.status}. Approve/Reject are disabled.
        </p>
      ) : null}

      <Link
        href={`/history?tenant_id=${encodeURIComponent(tenantId)}&entity_id=${encodeURIComponent(allocation.allocation_id)}`}
        className="inline-block text-sm text-accent hover:underline"
      >
        View change history for this allocation →
      </Link>
    </div>
  );
}
