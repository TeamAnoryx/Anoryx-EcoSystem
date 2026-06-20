import { Badge } from "@/components/ui/badge";
import { ErrorBanner } from "@/components/ui/error-banner";
import { ConfigForm } from "@/components/config/config-form";
import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";
import type { ConfigResponse } from "@/lib/types";

export default async function ConfigPage({ params }: { params: { tenantId: string } }) {
  let cfg: ConfigResponse | null = null;
  let error: string | null = null;
  try {
    cfg = await adminApi.getConfig(params.tenantId);
  } catch (e) {
    error = toFriendlyError(e).message;
  }

  if (error) return <ErrorBanner message={error} />;
  if (!cfg) return null;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <p className="text-sm text-fg-muted">Per-tenant classifier &amp; rate-limit configuration.</p>
        <Badge tone={cfg.configured ? "ok" : "neutral"}>
          {cfg.configured ? "configured" : "defaults"}
        </Badge>
      </div>
      <ConfigForm tenantId={params.tenantId} initial={cfg} />
    </div>
  );
}
