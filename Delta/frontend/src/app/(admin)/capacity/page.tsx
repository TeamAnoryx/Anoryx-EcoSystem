import { ApplyRebalanceSuggestionButton } from "@/components/capacity/apply-rebalance-suggestion-button";
import { CreateTeamForm } from "@/components/capacity/create-team-form";
import { TaskTeamAssignSelect } from "@/components/capacity/task-team-assign-select";
import { TeamCapacityControl } from "@/components/capacity/team-capacity-control";
import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";

export const dynamic = "force-dynamic";

interface Search {
  tenant_id?: string;
  project_id?: string;
  sprint_id?: string;
}

export default function CapacityPage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();
  const projectId = searchParams.project_id?.trim();
  const sprintId = searchParams.sprint_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Team capacity</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Teams with an operator-declared per-sprint story-point capacity, task-to-team
          assignment, a deterministic utilization report, and an advisory-only rebalancing
          suggestion (<code className="font-mono text-xs">greedy_rebalance_v1</code>) — nothing
          moves automatically. No individual-level capacity/PTO data, no burnout or wellbeing
          signal (a future task). See{" "}
          <code className="font-mono text-xs">docs/adr/0016-delta-team-capacity-management.md</code>.
        </p>
      </div>

      <form
        method="GET"
        className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-bg-raised p-4"
      >
        <div className="min-w-[14rem] flex-1">
          <label htmlFor="tenant_id" className="block text-sm font-medium text-fg">
            Tenant UUID
          </label>
          <input
            id="tenant_id"
            name="tenant_id"
            type="text"
            required
            defaultValue={tenantId ?? ""}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg"
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </div>
        <div className="min-w-[14rem] flex-1">
          <label htmlFor="project_id" className="block text-sm font-medium text-fg">
            Project UUID
          </label>
          <input
            id="project_id"
            name="project_id"
            type="text"
            required
            defaultValue={projectId ?? ""}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg"
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </div>
        <div className="min-w-[14rem] flex-1">
          <label htmlFor="sprint_id" className="block text-sm font-medium text-fg">
            Sprint UUID
          </label>
          <input
            id="sprint_id"
            name="sprint_id"
            type="text"
            required
            defaultValue={sprintId ?? ""}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg"
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </div>
        <button
          type="submit"
          className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg"
        >
          Load
        </button>
      </form>

      {!tenantId ? (
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view its teams.</p>
      ) : (
        <TeamsForTenant tenantId={tenantId} projectId={projectId} sprintId={sprintId} />
      )}
    </div>
  );
}

async function TeamsForTenant({
  tenantId,
  projectId,
  sprintId,
}: {
  tenantId: string;
  projectId?: string;
  sprintId?: string;
}) {
  let teams;
  let loadError: string | null = null;
  try {
    teams = await adminApi.listTeams(tenantId);
  } catch (err) {
    loadError =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load teams.";
  }

  if (loadError) {
    return (
      <p role="alert" className="text-sm text-danger">
        {loadError}
      </p>
    );
  }

  return (
    <div className="space-y-6">
      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Teams</h2>
        {teams!.length === 0 ? (
          <p className="text-sm text-fg-faint">No teams yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Name</th>
                  <th className="py-1 font-medium">Capacity (points / sprint)</th>
                </tr>
              </thead>
              <tbody>
                {teams!.map((t) => (
                  <tr key={t.team_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{t.name}</td>
                    <td className="py-1.5">
                      <TeamCapacityControl
                        teamId={t.team_id}
                        tenantId={tenantId}
                        currentCapacity={t.capacity_points_per_sprint}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <CreateTeamForm tenantId={tenantId} />
      </section>

      {!projectId || !sprintId ? (
        <p className="text-sm text-fg-faint">
          Enter a project UUID and sprint UUID above to view task assignment, utilization, and
          rebalance suggestions for that sprint.
        </p>
      ) : (
        <SprintCapacity
          tenantId={tenantId}
          projectId={projectId}
          sprintId={sprintId}
          teams={teams!}
        />
      )}
    </div>
  );
}

async function SprintCapacity({
  tenantId,
  projectId,
  sprintId,
  teams,
}: {
  tenantId: string;
  projectId: string;
  sprintId: string;
  teams: Awaited<ReturnType<typeof adminApi.listTeams>>;
}) {
  let tasks, utilization, rebalance;
  let loadError: string | null = null;
  try {
    [tasks, utilization, rebalance] = await Promise.all([
      adminApi.listCapacityTasks(tenantId, projectId, sprintId),
      adminApi.getUtilizationReport(tenantId, projectId, sprintId),
      adminApi.getRebalanceReport(tenantId, projectId, sprintId),
    ]);
  } catch (err) {
    loadError =
      err instanceof AdminApiError
        ? toFriendlyError(err).message
        : "Could not load sprint capacity data.";
  }

  if (loadError) {
    return (
      <p role="alert" className="text-sm text-danger">
        {loadError}
      </p>
    );
  }

  return (
    <div className="space-y-6">
      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Task team assignment</h2>
        {tasks!.length === 0 ? (
          <p className="text-sm text-fg-faint">No tasks in this sprint yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Task</th>
                  <th className="py-1 pr-4 font-medium">Points</th>
                  <th className="py-1 font-medium">Team</th>
                </tr>
              </thead>
              <tbody>
                {tasks!.map((t) => (
                  <tr key={t.task_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{t.title}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {t.story_points ?? "—"}
                    </td>
                    <td className="py-1.5">
                      <TaskTeamAssignSelect
                        taskId={t.task_id}
                        tenantId={tenantId}
                        currentTeamId={t.team_id}
                        teams={teams}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <div>
          <h2 className="text-sm font-medium text-fg">Utilization</h2>
          <p className="text-xs text-fg-faint">
            Remaining (not-done) assigned story points against each team&apos;s declared
            capacity (<code className="font-mono">{utilization!.method}</code>) — a deterministic
            ratio, not a burnout or wellbeing measure.
          </p>
        </div>
        {utilization!.teams.length === 0 ? (
          <p className="text-sm text-fg-faint">No teams yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Team</th>
                  <th className="py-1 pr-4 font-medium">Capacity</th>
                  <th className="py-1 pr-4 font-medium">Remaining</th>
                  <th className="py-1 font-medium">Utilization</th>
                </tr>
              </thead>
              <tbody>
                {utilization!.teams.map((row) => (
                  <tr key={row.team_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{row.team_name}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {row.capacity_points_per_sprint}
                    </td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {row.remaining_points}
                    </td>
                    <td className="py-1.5 tabular-nums text-fg-muted">
                      {row.utilization_ratio === null
                        ? "undefined"
                        : `${Math.round(row.utilization_ratio * 100)}%`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <div>
          <h2 className="text-sm font-medium text-fg">Rebalance suggestions</h2>
          <p className="text-xs text-fg-faint">
            A deterministic greedy suggestion (
            <code className="font-mono">{rebalance!.method}</code>) — advisory only, nothing
            moves until you click Apply.
          </p>
        </div>
        {rebalance!.suggestions.length === 0 ? (
          <p className="text-sm text-fg-faint">No rebalancing needed right now.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Task</th>
                  <th className="py-1 pr-4 font-medium">Points</th>
                  <th className="py-1 pr-4 font-medium">From</th>
                  <th className="py-1 pr-4 font-medium">To</th>
                  <th className="py-1 font-medium">Action</th>
                </tr>
              </thead>
              <tbody>
                {rebalance!.suggestions.map((s) => (
                  <tr key={s.task_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{s.title}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">{s.story_points}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{s.from_team_name}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{s.to_team_name}</td>
                    <td className="py-1.5">
                      <ApplyRebalanceSuggestionButton
                        taskId={s.task_id}
                        tenantId={tenantId}
                        toTeamId={s.to_team_id}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
