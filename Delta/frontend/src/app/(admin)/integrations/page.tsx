import { CreateSystemForm } from "@/components/integrations/create-system-form";
import { RunSyncForm } from "@/components/integrations/run-sync-form";
import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import { formatMinorUnits } from "@/lib/money";
import type { ExternalSystemView } from "@/lib/types";

export const dynamic = "force-dynamic";

interface Search {
  tenant_id?: string;
  system_id?: string;
}

export default function IntegrationsPage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();
  const selectedSystemId = searchParams.system_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Integrations</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Corporate ERP / procurement / cloud-cost sync connectors. A generic
          registration + sync-ingestion + reconciliation-matching framework — NOT
          live OAuth/API integrations with NetSuite, SAP, Coupa, Ariba, AWS, GCP, or
          Azure. Each synced line item is matched against a D-014 purchase order or
          D-018 invoice by exact ID and amount/currency. Every sync run is recorded
          in Delta&apos;s D-009 hash-chained audit log.
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
        <button
          type="submit"
          className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg"
        >
          Load
        </button>
      </form>

      {!tenantId ? (
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view its integrations.</p>
      ) : (
        <IntegrationsForTenant tenantId={tenantId} selectedSystemId={selectedSystemId} />
      )}
    </div>
  );
}

async function IntegrationsForTenant({
  tenantId,
  selectedSystemId,
}: {
  tenantId: string;
  selectedSystemId?: string;
}) {
  let systems: ExternalSystemView[];
  let loadError: string | null = null;
  try {
    systems = await adminApi.listExternalSystems(tenantId);
  } catch (err) {
    loadError =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load systems.";
    systems = [];
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
      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Registered systems</h2>
        {systems.length === 0 ? (
          <p className="text-sm text-fg-faint">No external systems registered yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Name</th>
                  <th className="py-1 pr-4 font-medium">Type</th>
                  <th className="py-1 pr-4 font-medium">Vendor</th>
                  <th className="py-1 pr-4 font-medium">Status</th>
                  <th className="py-1 font-medium">View</th>
                </tr>
              </thead>
              <tbody>
                {systems.map((s) => (
                  <tr key={s.system_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{s.name}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{s.system_type}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{s.vendor_label}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{s.status}</td>
                    <td className="py-1.5">
                      <a
                        href={`/integrations?tenant_id=${tenantId}&system_id=${s.system_id}`}
                        className="text-xs text-accent underline"
                      >
                        {selectedSystemId === s.system_id ? "viewing" : "view runs"}
                      </a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <CreateSystemForm tenantId={tenantId} />
      </section>

      {selectedSystemId ? (
        <SystemDetail tenantId={tenantId} systemId={selectedSystemId} />
      ) : null}
    </div>
  );
}

async function SystemDetail({ tenantId, systemId }: { tenantId: string; systemId: string }) {
  let runs, reconciliation;
  let loadError: string | null = null;
  try {
    [runs, reconciliation] = await Promise.all([
      adminApi.listSyncRuns(tenantId, systemId),
      adminApi.getSystemReconciliation(tenantId, systemId),
    ]);
  } catch (err) {
    loadError =
      err instanceof AdminApiError
        ? toFriendlyError(err).message
        : "Could not load sync history.";
  }

  if (loadError) {
    return (
      <p role="alert" className="text-sm text-danger">
        {loadError}
      </p>
    );
  }

  return (
    <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
      <h2 className="text-sm font-medium text-fg">Sync runs</h2>

      <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
        <div className="rounded-md border border-border bg-bg-inset p-3">
          <dt className="text-xs text-fg-muted">Total runs</dt>
          <dd className="tabular-nums text-fg">{reconciliation!.total_runs}</dd>
        </div>
        <div className="rounded-md border border-border bg-bg-inset p-3">
          <dt className="text-xs text-fg-muted">Matched</dt>
          <dd className="tabular-nums text-fg">{reconciliation!.matched_count}</dd>
        </div>
        <div className="rounded-md border border-border bg-bg-inset p-3">
          <dt className="text-xs text-fg-muted">Amount mismatch</dt>
          <dd className="tabular-nums text-fg">
            {reconciliation!.mismatched_count} (
            {formatMinorUnits(reconciliation!.mismatched_amount_minor_units, "USD")})
          </dd>
        </div>
        <div className="rounded-md border border-border bg-bg-inset p-3">
          <dt className="text-xs text-fg-muted">Not found / unreconciled</dt>
          <dd className="tabular-nums text-fg">
            {reconciliation!.not_found_count} / {reconciliation!.unreconciled_count}
          </dd>
        </div>
      </dl>

      {runs!.length === 0 ? (
        <p className="text-sm text-fg-faint">No sync runs yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-fg-muted">
              <tr>
                <th className="py-1 pr-4 font-medium">Started</th>
                <th className="py-1 pr-4 font-medium">Triggered by</th>
                <th className="py-1 pr-4 font-medium">Ingested</th>
                <th className="py-1 pr-4 font-medium">Matched</th>
                <th className="py-1 pr-4 font-medium">Mismatched</th>
                <th className="py-1 font-medium">Not found / unrec.</th>
              </tr>
            </thead>
            <tbody>
              {runs!.map((r) => (
                <tr key={r.sync_run_id} className="border-t border-border">
                  <td className="py-1.5 pr-4 text-fg-muted">{r.started_at}</td>
                  <td className="py-1.5 pr-4 text-fg">{r.triggered_by}</td>
                  <td className="py-1.5 pr-4 tabular-nums text-fg-muted">{r.records_ingested}</td>
                  <td className="py-1.5 pr-4 tabular-nums text-fg-muted">{r.records_matched}</td>
                  <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                    {r.records_mismatched}
                  </td>
                  <td className="py-1.5 tabular-nums text-fg-muted">
                    {r.records_not_found} / {r.records_unreconciled}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <RunSyncForm tenantId={tenantId} systemId={systemId} />
    </section>
  );
}
