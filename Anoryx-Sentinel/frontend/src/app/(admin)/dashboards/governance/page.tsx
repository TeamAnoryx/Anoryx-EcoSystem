import type { ReactNode } from "react";

import { ConfigForm } from "@/components/config/config-form";
import { SelectTenantNotice } from "@/components/dashboards/empty-state";
import { ShadowAiFeed } from "@/components/dashboards/shadow-ai-feed";
import { ErrorBanner } from "@/components/ui/error-banner";
import { adminApi } from "@/lib/admin-client";
import { PROVIDERS, filterShadowAiEvents } from "@/lib/dashboards";
import { fetchRecentAudit } from "@/lib/dashboards-server";
import { toFriendlyError } from "@/lib/errors";

export const dynamic = "force-dynamic";

/**
 * Governance dashboard (F-013). Scoped to ?tenant=. Shows the (partial) model
 * inventory — the static provider set + the tenant's configured classifier (full
 * inventory deferred, ADR-0016 2d) — reuses ConfigForm for classifier/audit/RPM
 * adjust, and renders the progressive shadow-AI detection feed.
 */
export default async function GovernanceDashboardPage({
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
      const [config, recent] = await Promise.all([
        adminApi.getConfig(tenant),
        fetchRecentAudit(tenant, 200),
      ]);
      const shadow = [...filterShadowAiEvents(recent.events)].reverse();
      body = (
        <div className="space-y-8">
          <section className="space-y-2" aria-label="Model inventory">
            <h2 className="text-sm font-medium text-fg-muted">Model inventory</h2>
            <div className="flex flex-wrap gap-2">
              {PROVIDERS.map((p) => (
                <span
                  key={p}
                  className="rounded-md border border-border bg-bg-inset px-2 py-1 font-mono text-xs text-fg"
                >
                  {p}
                </span>
              ))}
            </div>
            <p className="text-sm text-fg-muted">
              Configured classifier:{" "}
              <span className="font-mono text-fg">{config.classifier_model_id || "(unset)"}</span>
            </p>
            <p className="text-xs text-fg-faint">
              Provider set is the known upstream list; a full per-tenant model inventory is not
              exposed by the admin API (deferred, see ADR-0016).
            </p>
          </section>

          <section className="space-y-2" aria-label="Classifier and config">
            <h2 className="text-sm font-medium text-fg-muted">Classifier &amp; tenant config</h2>
            <ConfigForm tenantId={tenant} initial={config} />
          </section>

          <ShadowAiFeed events={shadow} />
        </div>
      );
    } catch (e) {
      body = <ErrorBanner message={toFriendlyError(e).message} />;
    }
  }

  return (
    <section className="space-y-6">
      <h1 className="text-xl font-semibold text-fg">Governance</h1>
      {body}
    </section>
  );
}
