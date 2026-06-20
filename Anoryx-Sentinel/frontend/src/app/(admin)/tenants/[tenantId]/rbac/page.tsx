import { Badge } from "@/components/ui/badge";
import { ErrorBanner } from "@/components/ui/error-banner";
import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";
import type { KeyListResponse, KeyResponse } from "@/lib/types";

/**
 * Read-only RBAC view. F-012a is single-operator — there is no RBAC management
 * surface. This derives the team → project → agent structure from key metadata,
 * honestly labelled. No new RBAC model (R7 / dispatch scope).
 */
export default async function RbacPage({ params }: { params: { tenantId: string } }) {
  let data: KeyListResponse | null = null;
  let error: string | null = null;
  try {
    data = await adminApi.listKeys(params.tenantId);
  } catch (e) {
    error = toFriendlyError(e).message;
  }

  const byTeam = new Map<string, Map<string, KeyResponse[]>>();
  for (const k of data?.keys ?? []) {
    if (!byTeam.has(k.team_id)) byTeam.set(k.team_id, new Map());
    const projects = byTeam.get(k.team_id)!;
    if (!projects.has(k.project_id)) projects.set(k.project_id, []);
    projects.get(k.project_id)!.push(k);
  }

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-border bg-bg-raised px-4 py-3 text-xs text-fg-muted">
        Derived from virtual-key metadata. Single-operator deployment — RBAC is not
        managed here (SSO &amp; roles are deferred to F-014).
      </div>

      {error ? <ErrorBanner message={error} /> : null}

      {data ? (
        byTeam.size === 0 ? (
          <p className="text-sm text-fg-muted">No keys, so no team/project structure to show.</p>
        ) : (
          <div className="space-y-4">
            {[...byTeam.entries()].map(([teamId, projects]) => (
              <div key={teamId} className="rounded-lg border border-border">
                <div className="border-b border-border bg-bg-raised px-4 py-2">
                  <span className="text-xs uppercase text-fg-faint">Team</span>{" "}
                  <span className="font-mono text-xs text-fg">{teamId}</span>
                </div>
                <div className="divide-y divide-border">
                  {[...projects.entries()].map(([projectId, keys]) => (
                    <div key={projectId} className="px-4 py-3">
                      <div className="font-mono text-xs text-fg-muted">project {projectId}</div>
                      <ul className="mt-2 flex flex-wrap gap-2">
                        {keys.map((k) => (
                          <li key={k.key_id}>
                            <Badge tone={k.is_active ? "ok" : "neutral"}>{k.agent_id}</Badge>
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )
      ) : null}
    </div>
  );
}
