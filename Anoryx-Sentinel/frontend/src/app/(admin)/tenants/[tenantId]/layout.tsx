import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { ErrorBanner } from "@/components/ui/error-banner";
import { TenantTabs } from "@/components/tenants/tenant-tabs";
import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";
import type { TenantResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function TenantLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: { tenantId: string };
}) {
  let tenant: TenantResponse | null = null;
  let error: string | null = null;
  try {
    tenant = await adminApi.getTenant(params.tenantId);
  } catch (e) {
    error = toFriendlyError(e).message;
  }

  return (
    <section className="space-y-4">
      <Link href="/tenants" className="text-xs text-fg-muted hover:text-fg">
        ← All tenants
      </Link>

      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-fg">
          {tenant ? tenant.display_name || tenant.name : "Tenant"}
        </h1>
        {tenant ? (
          <Badge tone={tenant.is_active ? "ok" : "neutral"}>
            {tenant.is_active ? "active" : "inactive"}
          </Badge>
        ) : null}
      </div>
      <p className="font-mono text-xs text-fg-faint">{params.tenantId}</p>

      {error ? <ErrorBanner message={error} /> : null}

      <TenantTabs tenantId={params.tenantId} />
      <div className="pt-2">{children}</div>
    </section>
  );
}
