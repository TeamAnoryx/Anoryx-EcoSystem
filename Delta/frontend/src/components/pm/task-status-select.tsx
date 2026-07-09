"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { updateTaskStatusAction } from "@/app/(admin)/pm/actions";
import type { TaskStatus } from "@/lib/types";

const STATUSES: TaskStatus[] = ["todo", "in_progress", "blocked", "done"];

/** Task status is deliberately reopenable (unlike D-013/D-014's forward-only
 * lifecycles) — a plain select. Marking "done" stamps completed_at server-side;
 * moving off "done" clears it. */
export function TaskStatusSelect({
  taskId,
  tenantId,
  currentStatus,
}: {
  taskId: string;
  tenantId: string;
  currentStatus: TaskStatus;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onChange(status: TaskStatus) {
    if (status === currentStatus) return;
    setError(null);
    setBusy(true);
    const result = await updateTaskStatusAction(taskId, { tenant_id: tenantId, status });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    router.refresh();
  }

  return (
    <div className="flex items-center gap-1">
      <select
        value={currentStatus}
        disabled={busy}
        onChange={(e) => onChange(e.target.value as TaskStatus)}
        className="rounded-md border border-border bg-bg-raised px-1.5 py-1 text-xs text-fg disabled:opacity-50"
      >
        {STATUSES.map((s) => (
          <option key={s} value={s}>
            {s}
          </option>
        ))}
      </select>
      {error ? <span className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}
