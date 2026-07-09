"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { transitionAssetStatusAction } from "@/app/(admin)/erp/actions";
import type { AssetStatus } from "@/lib/types";

const NEXT_STATUS: Record<AssetStatus, AssetStatus | null> = {
  active: "retired",
  retired: "disposed",
  disposed: null,
};

/** Inline per-asset forward-only lifecycle control (D-014): active -> retired ->
 * disposed. Mirrors CRM's DealStageControl. */
export function AssetStatusControl({
  assetId,
  tenantId,
  currentStatus,
}: {
  assetId: string;
  tenantId: string;
  currentStatus: AssetStatus;
}) {
  const router = useRouter();
  const [actor, setActor] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const next = NEXT_STATUS[currentStatus];
  if (next === null) {
    return <span className="text-xs text-fg-faint">final</span>;
  }

  async function submit() {
    setError(null);
    if (actor.trim().length === 0) {
      setError("Actor required");
      return;
    }
    setBusy(true);
    const result = await transitionAssetStatusAction(assetId, {
      tenant_id: tenantId,
      status: next as AssetStatus,
      actor: actor.trim(),
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    router.refresh();
  }

  return (
    <div className="flex flex-wrap items-center gap-1">
      <input
        type="text"
        value={actor}
        onChange={(e) => setActor(e.target.value)}
        placeholder="actor"
        className="w-20 rounded-md border border-border bg-bg-inset px-1.5 py-1 text-xs text-fg"
      />
      <button
        type="button"
        onClick={submit}
        disabled={busy}
        className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:border-accent hover:text-fg disabled:opacity-50"
      >
        {next}
      </button>
      {error ? <span className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}
