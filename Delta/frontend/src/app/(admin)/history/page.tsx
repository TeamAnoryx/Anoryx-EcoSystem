import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import type { ChangeHistoryEntryView } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function HistoryPage({
  searchParams,
}: {
  searchParams: { tenant_id?: string; entity_id?: string };
}) {
  const tenantId = searchParams.tenant_id?.trim();
  const entityId = searchParams.entity_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Change history</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Newest first. Optionally scoped to a single allocation via the entity_id filter.
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
        <div className="min-w-[16rem] flex-1">
          <label htmlFor="entity_id" className="block text-sm font-medium text-fg">
            Allocation id (optional)
          </label>
          <input
            id="entity_id"
            name="entity_id"
            type="text"
            defaultValue={entityId ?? ""}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg"
            placeholder="filter to one allocation"
          />
        </div>
        <button type="submit" className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg">
          Load
        </button>
      </form>

      {!tenantId ? (
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view its change history.</p>
      ) : (
        <HistoryForTenant tenantId={tenantId} entityId={entityId} />
      )}
    </div>
  );
}

async function HistoryForTenant({ tenantId, entityId }: { tenantId: string; entityId: string | undefined }) {
  let entries: ChangeHistoryEntryView[];
  let loadError: string | null = null;
  try {
    entries = await adminApi.listHistory(tenantId, entityId ? "allocation" : undefined, entityId);
  } catch (err) {
    entries = [];
    loadError = err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load history.";
  }

  if (loadError) {
    return (
      <p role="alert" className="text-sm text-danger">
        {loadError}
      </p>
    );
  }

  if (entries.length === 0) {
    return <p className="text-sm text-fg-faint">No history entries found for this tenant/filter.</p>;
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <table className="w-full text-left text-sm">
        <thead className="bg-bg-raised text-fg-muted">
          <tr>
            <th className="px-3 py-2 font-medium">When</th>
            <th className="px-3 py-2 font-medium">Action</th>
            <th className="px-3 py-2 font-medium">Actor</th>
            <th className="px-3 py-2 font-medium">Entity</th>
            <th className="px-3 py-2 font-medium">Note</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.history_id} className="border-t border-border">
              <td className="px-3 py-2 text-fg-muted">{e.created_at}</td>
              <td className="px-3 py-2">{e.action}</td>
              <td className="px-3 py-2">{e.actor}</td>
              <td className="px-3 py-2 font-mono text-xs">
                {e.entity_type}/{e.entity_id}
              </td>
              <td className="px-3 py-2 text-fg-muted">{e.note ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
