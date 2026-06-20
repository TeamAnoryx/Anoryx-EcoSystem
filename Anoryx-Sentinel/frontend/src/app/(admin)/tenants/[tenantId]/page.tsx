import { ErrorBanner } from "@/components/ui/error-banner";
import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";
import { formatTs } from "@/lib/format";
import type { TenantResponse } from "@/lib/types";

export default async function TenantOverviewPage({ params }: { params: { tenantId: string } }) {
  let t: TenantResponse | null = null;
  let error: string | null = null;
  try {
    t = await adminApi.getTenant(params.tenantId);
  } catch (e) {
    error = toFriendlyError(e).message;
  }

  if (error) return <ErrorBanner message={error} />;
  if (!t) return null;

  const rows: Array<[string, string]> = [
    ["Name", t.name],
    ["Display name", t.display_name || "—"],
    ["Status", t.is_active ? "active" : "inactive"],
    ["Created", formatTs(t.created_at)],
    ["Updated", formatTs(t.updated_at)],
  ];

  return (
    <dl className="grid max-w-xl grid-cols-3 gap-x-4 gap-y-3 rounded-lg border border-border bg-bg-raised p-4 text-sm">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="col-span-1 text-fg-muted">{k}</dt>
          <dd className="col-span-2 text-fg">{v}</dd>
        </div>
      ))}
    </dl>
  );
}
