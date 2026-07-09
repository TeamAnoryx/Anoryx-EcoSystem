"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { assignTaskTeamAction } from "@/app/(admin)/capacity/actions";

/** Applies one advisory rebalance suggestion by calling the SAME task-team-assign
 * action a human would use manually — the rebalance report itself never mutates
 * anything (ADR-0016 Fork 1). This button is just a convenience shortcut. */
export function ApplyRebalanceSuggestionButton({
  taskId,
  tenantId,
  toTeamId,
}: {
  taskId: string;
  tenantId: string;
  toTeamId: string;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function apply() {
    setError(null);
    setBusy(true);
    const result = await assignTaskTeamAction(taskId, { tenant_id: tenantId, team_id: toTeamId });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    router.refresh();
  }

  return (
    <div className="flex items-center gap-1">
      <button
        type="button"
        onClick={apply}
        disabled={busy}
        className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:border-accent hover:text-fg disabled:opacity-50"
      >
        {busy ? "Applying…" : "Apply"}
      </button>
      {error ? <span className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}
