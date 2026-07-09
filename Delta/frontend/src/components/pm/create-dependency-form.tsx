"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { createDependencyAction } from "@/app/(admin)/pm/actions";
import type { TaskView } from "@/lib/types";

export function CreateDependencyForm({
  tenantId,
  tasks,
}: {
  tenantId: string;
  tasks: TaskView[];
}) {
  const router = useRouter();
  const [blockingId, setBlockingId] = useState(tasks[0]?.task_id ?? "");
  const [blockedId, setBlockedId] = useState(tasks[1]?.task_id ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!tasks.some((t) => t.task_id === blockingId)) {
      setBlockingId(tasks[0]?.task_id ?? "");
    }
    if (!tasks.some((t) => t.task_id === blockedId)) {
      setBlockedId(tasks[1]?.task_id ?? "");
    }
  }, [tasks, blockingId, blockedId]);

  async function submit() {
    setError(null);
    if (!blockingId || !blockedId) {
      setError("Add at least two tasks first.");
      return;
    }
    if (blockingId === blockedId) {
      setError("A task cannot block itself.");
      return;
    }
    setBusy(true);
    const result = await createDependencyAction({
      tenant_id: tenantId,
      blocking_task_id: blockingId,
      blocked_task_id: blockedId,
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    router.refresh();
  }

  if (tasks.length < 2) {
    return <p className="text-xs text-fg-faint">Add at least two tasks to link a dependency.</p>;
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 items-center gap-2 sm:grid-cols-[1fr_auto_1fr_auto]">
        <select
          value={blockingId}
          onChange={(e) => setBlockingId(e.target.value)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {tasks.map((t) => (
            <option key={t.task_id} value={t.task_id}>
              {t.title}
            </option>
          ))}
        </select>
        <span className="text-center text-xs text-fg-muted">blocks →</span>
        <select
          value={blockedId}
          onChange={(e) => setBlockedId(e.target.value)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {tasks.map((t) => (
            <option key={t.task_id} value={t.task_id}>
              {t.title}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Linking…" : "Link"}
        </button>
      </div>
      {error ? (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      ) : null}
    </div>
  );
}
