import { type ReactNode, Suspense } from "react";

import { SelectTenantNotice } from "@/components/dashboards/empty-state";
import { DEFAULT_FRAMEWORK, FrameworkSelect } from "@/components/dashboards/framework-select";
import { GapSummary } from "@/components/dashboards/gap-summary";
import { ErrorBanner } from "@/components/ui/error-banner";
import { adminApi } from "@/lib/admin-client";
import { DEFAULT_WINDOW, isWindowKey, toReadinessView, windowRange } from "@/lib/dashboards";
import { toFriendlyError } from "@/lib/errors";

export const dynamic = "force-dynamic";

/**
 * Compliance dashboard (F-013). Scoped to ?tenant=, ?framework=, ?window=. Calls
 * the F-011 operator evidence path through the BFF and renders readiness +
 * status totals with honest "audit-ready, not compliant" framing (R6). The
 * per-control gap list and the signed pack download are deferred (ADR-0016 2b/2c).
 */
export default async function ComplianceDashboardPage({
  searchParams,
}: {
  searchParams: { tenant?: string; framework?: string; window?: string };
}) {
  const tenant = searchParams.tenant;
  const framework =
    searchParams.framework === "ISO27001" || searchParams.framework === "SOC2"
      ? searchParams.framework
      : DEFAULT_FRAMEWORK;
  const windowKey = isWindowKey(searchParams.window) ? searchParams.window : DEFAULT_WINDOW;

  let body: ReactNode;
  if (!tenant) {
    body = <SelectTenantNotice />;
  } else {
    const { t0, t1 } = windowRange(windowKey, Date.now());
    try {
      const ev = await adminApi.operatorEvidence(tenant, { framework, t0, t1 });
      body = (
        <div className="space-y-6">
          <GapSummary view={toReadinessView(ev)} />
          <PackDownloadDeferred />
        </div>
      );
    } catch (e) {
      body = <ErrorBanner message={toFriendlyError(e).message} />;
    }
  }

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold text-fg">Compliance</h1>
        <Suspense fallback={null}>
          <FrameworkSelect />
        </Suspense>
      </div>
      {body}
    </section>
  );
}

/**
 * Evidence-pack download is deferred (ADR-0016 2c): the signed-ZIP generator is
 * wired to no HTTP route, and the JSON-only BFF cannot stream the bytes intact
 * (R4). Shown disabled + labeled rather than hidden, so the gap is honest.
 */
function PackDownloadDeferred() {
  return (
    <div className="rounded-lg border border-dashed border-border-strong bg-bg-raised p-4">
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          disabled
          aria-disabled="true"
          className="cursor-not-allowed rounded-md border border-border px-4 py-2 text-sm text-fg-faint"
        >
          Download evidence pack (.zip)
        </button>
        <span className="text-xs text-fg-faint">
          Signed-pack download is a backend follow-up — no download endpoint yet, and byte-exact
          streaming needs a binary-safe path (ADR-0016).
        </span>
      </div>
    </div>
  );
}
