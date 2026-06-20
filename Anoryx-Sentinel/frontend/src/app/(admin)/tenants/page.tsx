import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { ErrorBanner } from "@/components/ui/error-banner";
import { CreateTenantForm } from "@/components/tenants/create-tenant-form";
import { DeactivateTenantButton } from "@/components/tenants/deactivate-tenant-button";
import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";
import { formatTs } from "@/lib/format";
import type { TenantListResponse } from "@/lib/types";

export default async function TenantsPage() {
  let data: TenantListResponse | null = null;
  let error: string | null = null;
  try {
    data = await adminApi.listTenants();
  } catch (e) {
    error = toFriendlyError(e).message;
  }

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-fg">Tenants</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Create, inspect, and deactivate tenants. {data ? `${data.count} total.` : ""}
        </p>
      </div>

      <div className="rounded-lg border border-border bg-bg-raised p-4">
        <CreateTenantForm />
      </div>

      {error ? <ErrorBanner message={error} /> : null}

      {data ? (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-raised text-xs uppercase text-fg-faint">
              <tr>
                <th scope="col" className="px-4 py-2">Name</th>
                <th scope="col" className="px-4 py-2">Tenant ID</th>
                <th scope="col" className="px-4 py-2">Status</th>
                <th scope="col" className="px-4 py-2">Created</th>
                <th scope="col" className="px-4 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {data.tenants.map((t) => (
                <tr key={t.tenant_id} className="hover:bg-bg-raised/50">
                  <td className="px-4 py-2">
                    <Link href={`/tenants/${t.tenant_id}`} className="text-accent hover:underline">
                      {t.display_name || t.name}
                    </Link>
                    <div className="text-xs text-fg-faint">{t.name}</div>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-fg-muted">{t.tenant_id}</td>
                  <td className="px-4 py-2">
                    <Badge tone={t.is_active ? "ok" : "neutral"}>
                      {t.is_active ? "active" : "inactive"}
                    </Badge>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-fg-muted">{formatTs(t.created_at)}</td>
                  <td className="px-4 py-2 text-right">
                    {t.is_active ? (
                      <DeactivateTenantButton tenantId={t.tenant_id} name={t.name} />
                    ) : (
                      <span className="text-xs text-fg-faint">—</span>
                    )}
                  </td>
                </tr>
              ))}
              {data.tenants.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-sm text-fg-muted">
                    No tenants yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
