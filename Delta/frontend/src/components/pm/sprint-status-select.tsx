"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { updateSprintStatusAction } from "@/app/(admin)/pm/actions";
import type { SprintStatus } from "@/lib/types";

const STATUSES: SprintStatus[] = ["planned", "active", "completed"];

/** Sprint status is free-form (not forward-only like D-013/D-014's lifecycles) — a
 * plain select, mirroring TaskStatusSelect. */
export function SprintStatusSelect({
  sprintId,
  tenantId,
  currentStatus,
}: {
  sprintId: string;
  tenantId: string;
  currentStatus: SprintStatus;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onChange(status: SprintStatus) {
    if (status === currentStatus) return;
    setError(null);
    setBusy(true);
    const result = await updateSprintStatusAction(sprintId, { tenant_id: tenantId, status });
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
        onChange={(e) => onChange(e.target.value as SprintStatus)}
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
