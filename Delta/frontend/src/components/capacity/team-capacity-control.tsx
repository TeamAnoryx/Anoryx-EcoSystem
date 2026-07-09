"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { updateTeamCapacityAction } from "@/app/(admin)/capacity/actions";

export function TeamCapacityControl({
  teamId,
  tenantId,
  currentCapacity,
}: {
  teamId: string;
  tenantId: string;
  currentCapacity: number;
}) {
  const router = useRouter();
  const [capacity, setCapacity] = useState(String(currentCapacity));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    const capacityPoints = Number(capacity);
    if (!Number.isInteger(capacityPoints) || capacityPoints < 0) {
      setError("Must be a non-negative whole number.");
      return;
    }
    if (capacityPoints === currentCapacity) return;
    setBusy(true);
    const result = await updateTeamCapacityAction(teamId, {
      tenant_id: tenantId,
      capacity_points_per_sprint: capacityPoints,
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    router.refresh();
  }

  return (
    <div className="flex items-center gap-1">
      <input
        type="text"
        inputMode="numeric"
        value={capacity}
        onChange={(e) => setCapacity(e.target.value)}
        disabled={busy}
        className="w-20 rounded-md border border-border bg-bg-raised px-1.5 py-1 text-xs text-fg disabled:opacity-50"
      />
      <button
        type="button"
        onClick={submit}
        disabled={busy}
        className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:border-accent hover:text-fg disabled:opacity-50"
      >
        Update
      </button>
      {error ? <span className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}
