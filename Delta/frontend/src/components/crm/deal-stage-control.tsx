"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { transitionDealStageAction } from "@/app/(admin)/crm/actions";
import type { DealStage } from "@/lib/types";

const NEXT_STAGES: Record<DealStage, DealStage[]> = {
  lead: ["qualified", "lost"],
  qualified: ["proposal", "lost"],
  proposal: ["negotiation", "lost"],
  negotiation: ["won", "lost"],
  won: [],
  lost: [],
};

/** Inline per-deal stage-transition control (D-013). Terminal deals ('won'/'lost')
 * render no options — the 409 from an already-terminal deal is a real, expected
 * outcome (mirrors allocations' DecisionButtons "already decided" handling). */
export function DealStageControl({
  clientId,
  dealId,
  tenantId,
  currentStage,
}: {
  clientId: string;
  dealId: string;
  tenantId: string;
  currentStage: DealStage;
}) {
  const router = useRouter();
  const [actor, setActor] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const options = NEXT_STAGES[currentStage];
  if (options.length === 0) {
    return <span className="text-xs text-fg-faint">final</span>;
  }

  async function submit(stage: DealStage) {
    setError(null);
    if (actor.trim().length === 0) {
      setError("Actor required");
      return;
    }
    setBusy(true);
    const result = await transitionDealStageAction(clientId, dealId, {
      tenant_id: tenantId,
      stage,
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
      {options.map((stage) => (
        <button
          key={stage}
          type="button"
          onClick={() => submit(stage)}
          disabled={busy}
          className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:border-accent hover:text-fg disabled:opacity-50"
        >
          {stage}
        </button>
      ))}
      {error ? <span className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}
