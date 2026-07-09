import Link from "next/link";

import { CreateClientForm } from "@/components/crm/create-client-form";
import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";

export const dynamic = "force-dynamic";

interface Search {
  tenant_id?: string;
}

export default function CrmPage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Unified CRM</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Client records, a deal pipeline, a stakeholder roster, and interaction history over the
          D-003 ledger&apos;s tenant scope. Relationship scores are a deterministic recency +
          frequency heuristic — not a trained or validated statistical/ML model.
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
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view its clients.</p>
      ) : (
        <div className="space-y-6">
          <CreateClientForm tenantId={tenantId} />
          <ClientList tenantId={tenantId} />
        </div>
      )}
    </div>
  );
}

async function ClientList({ tenantId }: { tenantId: string }) {
  let clients;
  let loadError: string | null = null;
  try {
    clients = await adminApi.listClients(tenantId);
  } catch (err) {
    loadError =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load clients.";
  }

  if (loadError) {
    return (
      <p role="alert" className="text-sm text-danger">
        {loadError}
      </p>
    );
  }

  return (
    <section className="rounded-lg border border-border bg-bg-raised p-4">
      <h2 className="mb-3 text-sm font-medium text-fg">Clients</h2>
      {clients!.length === 0 ? (
        <p className="text-sm text-fg-faint">No clients yet for this tenant.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-fg-muted">
              <tr>
                <th className="py-1 pr-4 font-medium">Name</th>
                <th className="py-1 pr-4 font-medium">Primary contact</th>
                <th className="py-1 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {clients!.map((c) => (
                <tr key={c.client_id} className="border-t border-border">
                  <td className="py-1.5 pr-4">
                    <Link
                      href={`/crm/${c.client_id}?tenant_id=${encodeURIComponent(tenantId)}`}
                      className="text-accent hover:underline"
                    >
                      {c.name}
                    </Link>
                  </td>
                  <td className="py-1.5 pr-4 text-fg-muted">
                    {c.primary_contact_name ?? c.primary_contact_email ?? "—"}
                  </td>
                  <td className="py-1.5 tabular-nums text-fg-muted">{c.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
