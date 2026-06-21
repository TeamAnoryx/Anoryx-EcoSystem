"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import type { TenantResponse } from "@/lib/types";

/**
 * Tenant scope selector for the dashboards (F-013 R3). Selecting a tenant sets
 * `?tenant=<id>` on the current dashboard route; every switch is a fresh URL, so
 * the server page re-fetches scoped data and no prior-tenant state survives. The
 * tenant list is fetched server-side in the layout and passed in (no token in
 * the browser). Tenant ids/names render as inert text (R5).
 */
export function TenantPicker({ tenants }: { tenants: TenantResponse[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const selected = params.get("tenant") ?? "";

  function onChange(tenantId: string) {
    const next = new URLSearchParams(params.toString());
    if (tenantId) next.set("tenant", tenantId);
    else next.delete("tenant");
    const qs = next.toString();
    router.push(qs ? `${pathname}?${qs}` : pathname);
  }

  return (
    <div className="flex items-center gap-2">
      <label htmlFor="dash-tenant" className="text-xs font-medium text-fg-muted">
        Tenant
      </label>
      <select
        id="dash-tenant"
        value={selected}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-border bg-bg-inset px-3 py-1.5 text-sm text-fg"
      >
        <option value="">Select a tenant…</option>
        {tenants.map((t) => (
          <option key={t.tenant_id} value={t.tenant_id}>
            {t.display_name || t.name} {t.is_active ? "" : "(inactive)"}
          </option>
        ))}
      </select>
    </div>
  );
}
