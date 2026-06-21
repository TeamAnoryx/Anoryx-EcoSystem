import { Suspense } from "react";

import { TenantPicker } from "@/components/dashboards/tenant-picker";
import { WindowSelect } from "@/components/dashboards/window-select";
import { ErrorBanner } from "@/components/ui/error-banner";
import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";
import type { TenantResponse } from "@/lib/types";

// Dashboards are request-time dynamic (scoped to the selected tenant); never
// statically prerendered. Inherits the (admin) group session guard.
export const dynamic = "force-dynamic";

/**
 * Shared dashboard chrome (F-013, ADR-0016 D2). The tenant list is fetched
 * server-side here (token stays server-side) and handed to the client picker;
 * the picker + window selector read/write the URL so each tenant switch is a
 * fresh scoped server fetch (R3). Children are the individual dashboards.
 */
export default async function DashboardsLayout({ children }: { children: React.ReactNode }) {
  let tenants: TenantResponse[] = [];
  let error: string | null = null;
  try {
    tenants = (await adminApi.listTenants()).tenants;
  } catch (e) {
    error = toFriendlyError(e).message;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-border bg-bg-raised px-4 py-3">
        <Suspense fallback={null}>
          <TenantPicker tenants={tenants} />
        </Suspense>
        <Suspense fallback={null}>
          <WindowSelect />
        </Suspense>
      </div>
      {error ? <ErrorBanner message={error} /> : null}
      {children}
    </div>
  );
}
