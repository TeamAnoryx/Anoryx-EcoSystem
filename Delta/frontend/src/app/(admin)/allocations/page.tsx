import Link from "next/link";

import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import { formatMinorUnits } from "@/lib/money";
import type { AllocationStatus, AllocationView } from "@/lib/types";

import { CreateAllocationForm } from "@/components/allocations/create-allocation-form";

export const dynamic = "force-dynamic";

const TABS: Array<{ label: string; value: AllocationStatus | "all" }> = [
  { label: "Requested", value: "requested" },
  { label: "Approved", value: "approved" },
  { label: "Rejected", value: "rejected" },
  { label: "All", value: "all" },
];

function tabHref(tenantId: string, status: string) {
  const qp = new URLSearchParams({ tenant_id: tenantId });
  if (status !== "all") qp.set("status", status);
  return `/allocations?${qp.toString()}`;
}

export default async function AllocationsPage({
  searchParams,
}: {
  searchParams: { tenant_id?: string; status?: string };
}) {
  const tenantId = searchParams.tenant_id?.trim();
  const status = (searchParams.status as AllocationStatus | undefined) ?? undefined;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Allocations</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Delta has no tenant directory UI yet — enter the tenant UUID below to manage its
          allocations. This is a known limitation, not a bug.
        </p>
      </div>

      <form method="GET" className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-bg-raised p-4">
        <div className="flex-1 min-w-[16rem]">
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
        <button
          type="submit"
          className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg"
        >
          Load
        </button>
      </form>

      {!tenantId ? (
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view or create allocations.</p>
      ) : (
        <AllocationsForTenant tenantId={tenantId} status={status} />
      )}
    </div>
  );
}

async function AllocationsForTenant({
  tenantId,
  status,
}: {
  tenantId: string;
  status: AllocationStatus | undefined;
}) {
  let allocations: AllocationView[];
  let loadError: string | null = null;
  try {
    allocations = await adminApi.listAllocations(tenantId, status);
  } catch (err) {
    allocations = [];
    loadError =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load allocations.";
  }

  return (
    <div className="space-y-6">
      <div className="flex gap-1 border-b border-border">
        {TABS.map((tab) => (
          <Link
            key={tab.value}
            href={tabHref(tenantId, tab.value)}
            className={`px-3 py-2 text-sm font-medium ${
              (status ?? "all") === tab.value
                ? "border-b-2 border-accent text-fg"
                : "text-fg-muted hover:text-fg"
            }`}
          >
            {tab.label}
          </Link>
        ))}
      </div>

      {loadError ? (
        <p role="alert" className="text-sm text-danger">
          {loadError}
        </p>
      ) : allocations.length === 0 ? (
        <p className="text-sm text-fg-faint">No allocations found for this tenant/filter.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-raised text-fg-muted">
              <tr>
                <th className="px-3 py-2 font-medium">Allocation</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Total</th>
                <th className="px-3 py-2 font-medium">Period</th>
                <th className="px-3 py-2 font-medium">Requested by</th>
                <th className="px-3 py-2 font-medium">Requested at</th>
              </tr>
            </thead>
            <tbody>
              {allocations.map((a) => (
                <tr key={a.allocation_id} className="border-t border-border">
                  <td className="px-3 py-2 font-mono text-xs">
                    <Link
                      href={`/allocations/${a.allocation_id}?tenant_id=${encodeURIComponent(tenantId)}`}
                      className="text-accent hover:underline"
                    >
                      {a.allocation_id}
                    </Link>
                  </td>
                  <td className="px-3 py-2">{a.status}</td>
                  <td className="px-3 py-2">{formatMinorUnits(a.total_minor_units, a.currency)}</td>
                  <td className="px-3 py-2">{a.period}</td>
                  <td className="px-3 py-2">{a.requested_by}</td>
                  <td className="px-3 py-2 text-fg-muted">{a.requested_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <CreateAllocationForm tenantId={tenantId} />
    </div>
  );
}
