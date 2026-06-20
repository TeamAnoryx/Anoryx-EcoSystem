import { ErrorBanner } from "@/components/ui/error-banner";
import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";
import { formatTs } from "@/lib/format";
import type { PolicyListResponse } from "@/lib/types";

export default async function PoliciesPage({ params }: { params: { tenantId: string } }) {
  let data: PolicyListResponse | null = null;
  let error: string | null = null;
  try {
    data = await adminApi.listPolicies(params.tenantId);
  } catch (e) {
    error = toFriendlyError(e).message;
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-fg-muted">
        Policy intake status (F-008), read-only. {data ? `${data.count} active.` : ""}
      </p>
      {error ? <ErrorBanner message={error} /> : null}
      {data ? (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-raised text-xs uppercase text-fg-faint">
              <tr>
                <th scope="col" className="px-4 py-2">Policy ID</th>
                <th scope="col" className="px-4 py-2">Type</th>
                <th scope="col" className="px-4 py-2">Version</th>
                <th scope="col" className="px-4 py-2">Effective from</th>
                <th scope="col" className="px-4 py-2">Team / Project / Agent</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {data.policies.map((p) => (
                <tr key={p.policy_id} className="hover:bg-bg-raised/50">
                  <td className="px-4 py-2 font-mono text-xs text-fg-muted">{p.policy_id}</td>
                  <td className="px-4 py-2 text-fg">{p.policy_type}</td>
                  <td className="px-4 py-2 font-mono text-xs text-fg-muted">v{p.current_version}</td>
                  <td className="px-4 py-2 font-mono text-xs text-fg-muted">{formatTs(p.effective_from)}</td>
                  <td className="px-4 py-2 font-mono text-xs text-fg-muted">
                    {p.team_id} / {p.project_id} / {p.agent_id}
                  </td>
                </tr>
              ))}
              {data.policies.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-6 text-center text-sm text-fg-muted">
                    No policies for this tenant.
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
