import type { ReactNode } from "react";

import { ChainStatus } from "@/components/dashboards/chain-status";
import { SelectTenantNotice } from "@/components/dashboards/empty-state";
import { SecurityFeed } from "@/components/dashboards/security-feed";
import { ErrorBanner } from "@/components/ui/error-banner";
import { fetchRecentAudit } from "@/lib/dashboards-server";
import { toFriendlyError } from "@/lib/errors";

export const dynamic = "force-dynamic";

/**
 * Security dashboard (F-013). Scoped to ?tenant=. Server fetches the recent
 * audit tail (chain status + seed); the SecurityFeed island live-polls for new
 * events via the BFF. Per-team breakdown is client-aggregated; per-model is
 * deferred (no model field in the audit projection — ADR-0016).
 */
export default async function SecurityDashboardPage({
  searchParams,
}: {
  searchParams: { tenant?: string };
}) {
  const tenant = searchParams.tenant;
  let body: ReactNode;

  if (!tenant) {
    body = <SelectTenantNotice />;
  } else {
    try {
      const recent = await fetchRecentAudit(tenant, 200);
      body = (
        <>
          <ChainStatus verified={recent.chainVerified} rowsChecked={recent.chainRowsChecked} />
          <SecurityFeed
            key={tenant}
            tenantId={tenant}
            initialEvents={recent.events}
            initialLastSequence={recent.lastSequence}
          />
        </>
      );
    } catch (e) {
      body = <ErrorBanner message={toFriendlyError(e).message} />;
    }
  }

  return (
    <section className="space-y-4">
      <h1 className="text-xl font-semibold text-fg">Security</h1>
      {body}
    </section>
  );
}
