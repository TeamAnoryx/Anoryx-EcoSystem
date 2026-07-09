"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { assignTaskTeamAction } from "@/app/(admin)/capacity/actions";
import type { TeamView } from "@/lib/types";

export function TaskTeamAssignSelect({
  taskId,
  tenantId,
  currentTeamId,
  teams,
}: {
  taskId: string;
  tenantId: string;
  currentTeamId: string | null;
  teams: TeamView[];
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onChange(teamId: string) {
    const nextTeamId = teamId || null;
    if (nextTeamId === currentTeamId) return;
    setError(null);
    setBusy(true);
    const result = await assignTaskTeamAction(taskId, { tenant_id: tenantId, team_id: nextTeamId });
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
        value={currentTeamId ?? ""}
        disabled={busy}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-border bg-bg-raised px-1.5 py-1 text-xs text-fg disabled:opacity-50"
      >
        <option value="">Unassigned</option>
        {teams.map((t) => (
          <option key={t.team_id} value={t.team_id}>
            {t.name}
          </option>
        ))}
      </select>
      {error ? <span className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}
