import type { ReactNode } from "react";

import { ConfigForm } from "@/components/config/config-form";
import { SelectTenantNotice } from "@/components/dashboards/empty-state";
import { ModelGovernancePanel } from "@/components/dashboards/model-governance-panel";
import { ShadowAiFeed } from "@/components/dashboards/shadow-ai-feed";
import { ErrorBanner } from "@/components/ui/error-banner";
import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";

export const dynamic = "force-dynamic";

/**
 * Governance dashboard (F-013 + F-018 + F-021). Scoped to ?tenant=.
 *
 * Model inventory (F-021): replaced the static provider list (ADR-0016 deferral 2d)
 * with the live ModelGovernancePanel island — a polling client component that reads
 * `GET tenants/{id}/models` through the BFF and surfaces approve/deny/retire/un-retire
 * actions with inline confirmation (ADR-0024).
 *
 * Shadow-AI panel (F-018): live polling island that calls
 * `GET tenants/{id}/shadow-ai/candidates` through the BFF. The island owns its
 * own polling and renders the backend-supplied honesty disclaimer non-removably
 * (ADR-0021 §4 / R1).
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
      const config = await adminApi.getConfig(tenant);
      body = (
        <div className="space-y-8">
          {/*
            F-021: ModelGovernancePanel replaces the static provider list. The
            island polls GET tenants/{id}/models via the BFF and renders live
            per-tenant model inventory with approval/retirement actions.
            key={tenant} remounts the island on tenant switch (ADR-0022 isolation).
          */}
          <ModelGovernancePanel key={tenant} tenantId={tenant} />

          <section className="space-y-2" aria-label="Classifier and config">
            <h2 className="text-sm font-medium text-fg-muted">Classifier &amp; tenant config</h2>
            <p className="text-sm text-fg-muted">
              Configured classifier:{" "}
              <span className="font-mono text-fg">{config.classifier_model_id || "(unset)"}</span>
            </p>
            <ConfigForm tenantId={tenant} initial={config} />
          </section>

          {/*
            F-018: The ShadowAiFeed island manages its own polling via usePoll +
            clientApi.get. key={tenant} ensures the island remounts on tenant
            switch, clearing all prior-tenant state (ADR-0021 isolation / R3).
            No audit events are pre-fetched here — the island owns the data path.
          */}
          <ShadowAiFeed key={tenant} tenantId={tenant} />
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
