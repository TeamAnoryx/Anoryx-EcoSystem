import { CreateDependencyForm } from "@/components/pm/create-dependency-form";
import { CreateSprintForm } from "@/components/pm/create-sprint-form";
import { CreateTaskForm } from "@/components/pm/create-task-form";
import { SprintStatusSelect } from "@/components/pm/sprint-status-select";
import { TaskStatusSelect } from "@/components/pm/task-status-select";
import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";

export const dynamic = "force-dynamic";

interface Search {
  tenant_id?: string;
  project_id?: string;
}

export default function PmPage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();
  const projectId = searchParams.project_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Project management</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Sprints, tasks, and a task dependency graph, with a sprint-velocity report and a
          deterministic blocking-fan-out bottleneck heuristic (
          <code className="font-mono text-xs">blocking_fanout_v1</code>) — not a trained or
          validated ML prediction. No real-time push updates and no external issue-tracker sync
          yet (a future task). See{" "}
          <code className="font-mono text-xs">docs/adr/0015-delta-pm-sprints-dependencies.md</code>.
        </p>
      </div>

      <form
        method="GET"
        className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-bg-raised p-4"
      >
        <div className="min-w-[16rem] flex-1">
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
        <div className="min-w-[16rem] flex-1">
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
        <button
          type="submit"
          className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg"
        >
          Load
        </button>
      </form>

      {!tenantId || !projectId ? (
        <p className="text-sm text-fg-faint">
          Enter a tenant UUID and project UUID above to view its PM data.
        </p>
      ) : (
        <PmForProject tenantId={tenantId} projectId={projectId} />
      )}
    </div>
  );
}

async function PmForProject({ tenantId, projectId }: { tenantId: string; projectId: string }) {
  let sprints, tasks, velocity, bottlenecks;
  let loadError: string | null = null;
  try {
    [sprints, tasks, velocity, bottlenecks] = await Promise.all([
      adminApi.listSprints(tenantId, projectId),
      adminApi.listTasks(tenantId, projectId),
      adminApi.getVelocityReport(tenantId, projectId),
      adminApi.getBottleneckReport(tenantId, projectId),
    ]);
  } catch (err) {
    loadError =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load PM data.";
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
        <h2 className="text-sm font-medium text-fg">Sprints</h2>
        {sprints!.length === 0 ? (
          <p className="text-sm text-fg-faint">No sprints yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Name</th>
                  <th className="py-1 pr-4 font-medium">Start</th>
                  <th className="py-1 pr-4 font-medium">End</th>
                  <th className="py-1 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {sprints!.map((s) => (
                  <tr key={s.sprint_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{s.name}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">
                      {new Date(s.start_date).toLocaleDateString()}
                    </td>
                    <td className="py-1.5 pr-4 text-fg-muted">
                      {new Date(s.end_date).toLocaleDateString()}
                    </td>
                    <td className="py-1.5">
                      <SprintStatusSelect
                        sprintId={s.sprint_id}
                        tenantId={tenantId}
                        currentStatus={s.status}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <CreateSprintForm tenantId={tenantId} projectId={projectId} />
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Tasks</h2>
        {tasks!.length === 0 ? (
          <p className="text-sm text-fg-faint">No tasks yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Title</th>
                  <th className="py-1 pr-4 font-medium">Points</th>
                  <th className="py-1 pr-4 font-medium">Assignee</th>
                  <th className="py-1 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {tasks!.map((t) => (
                  <tr key={t.task_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{t.title}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {t.story_points ?? "—"}
                    </td>
                    <td className="py-1.5 pr-4 text-fg-muted">{t.assignee ?? "—"}</td>
                    <td className="py-1.5">
                      <TaskStatusSelect
                        taskId={t.task_id}
                        tenantId={tenantId}
                        currentStatus={t.status}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <CreateTaskForm tenantId={tenantId} projectId={projectId} sprints={sprints!} />
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Task dependencies</h2>
        <CreateDependencyForm tenantId={tenantId} tasks={tasks!} />
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Sprint velocity</h2>
        {velocity!.sprints.length === 0 ? (
          <p className="text-sm text-fg-faint">No sprint velocity data yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Sprint</th>
                  <th className="py-1 pr-4 font-medium">Status</th>
                  <th className="py-1 pr-4 font-medium">Completed points</th>
                  <th className="py-1 font-medium">Tasks done</th>
                </tr>
              </thead>
              <tbody>
                {velocity!.sprints.map((row) => (
                  <tr key={row.sprint_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{row.sprint_name}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{row.status}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {row.completed_story_points}
                    </td>
                    <td className="py-1.5 tabular-nums text-fg-muted">
                      {row.completed_task_count} / {row.total_task_count}
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
          <h2 className="text-sm font-medium text-fg">Bottlenecks</h2>
          <p className="text-xs text-fg-faint">
            Non-done tasks ranked by how many other tasks they directly block (
            <code className="font-mono">{bottlenecks!.method}</code>) — a fixed heuristic, not a
            trained or validated prediction.
          </p>
        </div>
        {bottlenecks!.bottlenecks.length === 0 ? (
          <p className="text-sm text-fg-faint">No bottlenecks right now.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Task</th>
                  <th className="py-1 pr-4 font-medium">Status</th>
                  <th className="py-1 font-medium">Blocking count</th>
                </tr>
              </thead>
              <tbody>
                {bottlenecks!.bottlenecks.map((row) => (
                  <tr key={row.task_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{row.title}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{row.status}</td>
                    <td className="py-1.5 tabular-nums text-fg-muted">{row.blocking_count}</td>
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
