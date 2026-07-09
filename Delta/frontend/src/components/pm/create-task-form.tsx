"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { createTaskAction } from "@/app/(admin)/pm/actions";
import type { SprintView } from "@/lib/types";

export function CreateTaskForm({
  tenantId,
  projectId,
  sprints,
}: {
  tenantId: string;
  projectId: string;
  sprints: SprintView[];
}) {
  const router = useRouter();
  const [title, setTitle] = useState("");
  const [sprintId, setSprintId] = useState("");
  const [storyPoints, setStoryPoints] = useState("");
  const [assignee, setAssignee] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Same stale-prop-after-router.refresh() concern D-014's CreatePoForm hit:
  // re-sync the selected sprint whenever it drops out of the current list.
  useEffect(() => {
    if (sprintId && !sprints.some((s) => s.sprint_id === sprintId)) {
      setSprintId("");
    }
  }, [sprints, sprintId]);

  async function submit() {
    setError(null);
    if (title.trim().length === 0) {
      setError("Title is required.");
      return;
    }
    let points: number | undefined;
    if (storyPoints.trim().length > 0) {
      points = Number(storyPoints);
      if (!Number.isInteger(points) || points < 0) {
        setError("Story points must be a non-negative whole number.");
        return;
      }
    }
    setBusy(true);
    const result = await createTaskAction({
      tenant_id: tenantId,
      project_id: projectId,
      sprint_id: sprintId || undefined,
      title: title.trim(),
      story_points: points,
      assignee: assignee.trim() || undefined,
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setTitle("");
    setStoryPoints("");
    setAssignee("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-5">
        <input
          type="text"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Task title"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg sm:col-span-2"
        />
        <select
          value={sprintId}
          onChange={(e) => setSprintId(e.target.value)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          <option value="">No sprint</option>
          {sprints.map((s) => (
            <option key={s.sprint_id} value={s.sprint_id}>
              {s.name}
            </option>
          ))}
        </select>
        <input
          type="text"
          inputMode="numeric"
          value={storyPoints}
          onChange={(e) => setStoryPoints(e.target.value)}
          placeholder="Points"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <input
          type="text"
          value={assignee}
          onChange={(e) => setAssignee(e.target.value)}
          placeholder="Assignee (optional)"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
      </div>
      <button
        type="button"
        onClick={submit}
        disabled={busy}
        className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
      >
        {busy ? "Creating…" : "Add task"}
      </button>
      {error ? (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      ) : null}
    </div>
  );
}
