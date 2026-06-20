import { Badge } from "@/components/ui/badge";
import { ErrorBanner } from "@/components/ui/error-banner";
import { KeyRowActions } from "@/components/keys/key-row-actions";
import { MintKeyForm } from "@/components/keys/mint-key-form";
import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";
import { formatTs } from "@/lib/format";
import type { KeyListResponse } from "@/lib/types";

export default async function KeysPage({ params }: { params: { tenantId: string } }) {
  let data: KeyListResponse | null = null;
  let error: string | null = null;
  try {
    data = await adminApi.listKeys(params.tenantId);
  } catch (e) {
    error = toFriendlyError(e).message;
  }

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="mb-3 text-sm font-medium text-fg">Mint a virtual key</h2>
        <MintKeyForm tenantId={params.tenantId} />
      </div>

      {error ? <ErrorBanner message={error} /> : null}

      {data ? (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-raised text-xs uppercase text-fg-faint">
              <tr>
                <th scope="col" className="px-4 py-2">Key ID</th>
                <th scope="col" className="px-4 py-2">Team / Project / Agent</th>
                <th scope="col" className="px-4 py-2">Label</th>
                <th scope="col" className="px-4 py-2">Status</th>
                <th scope="col" className="px-4 py-2">Last used</th>
                <th scope="col" className="px-4 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {data.keys.map((k) => (
                <tr key={k.key_id} className="hover:bg-bg-raised/50">
                  <td className="px-4 py-2 font-mono text-xs text-fg-muted">{k.key_id}</td>
                  <td className="px-4 py-2 font-mono text-xs text-fg-muted">
                    {k.team_id}
                    <br />
                    {k.project_id}
                    <br />
                    {k.agent_id}
                  </td>
                  <td className="px-4 py-2 text-fg">{k.label || "—"}</td>
                  <td className="px-4 py-2">
                    <Badge tone={k.is_active ? "ok" : "neutral"}>
                      {k.is_active ? "active" : "revoked"}
                    </Badge>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-fg-muted">
                    {formatTs(k.last_used_at)}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <KeyRowActions tenantId={params.tenantId} keyId={k.key_id} isActive={k.is_active} />
                  </td>
                </tr>
              ))}
              {data.keys.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-sm text-fg-muted">
                    No keys for this tenant yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
