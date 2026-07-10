"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { decideInvoiceAction } from "@/app/(admin)/invoicing/actions";

/** Inline approve/dispute controls for a 'submitted' invoice (D-018). Mirrors
 * erp/po-decision-buttons.tsx. */
export function InvoiceDecisionButtons({
  invoiceId,
  tenantId,
}: {
  invoiceId: string;
  tenantId: string;
}) {
  const router = useRouter();
  const [actor, setActor] = useState("");
  const [busyAction, setBusyAction] = useState<"approve" | "dispute" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(action: "approve" | "dispute") {
    setError(null);
    if (actor.trim().length === 0) {
      setError("Actor required");
      return;
    }
    setBusyAction(action);
    const result = await decideInvoiceAction(invoiceId, {
      tenant_id: tenantId,
      action,
      actor: actor.trim(),
    });
    setBusyAction(null);
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
        onClick={() => submit("approve")}
        disabled={busyAction !== null}
        className="rounded-md bg-ok px-2 py-1 text-xs font-semibold text-accent-fg disabled:opacity-50"
      >
        {busyAction === "approve" ? "…" : "Approve"}
      </button>
      <button
        type="button"
        onClick={() => submit("dispute")}
        disabled={busyAction !== null}
        className="rounded-md bg-danger px-2 py-1 text-xs font-semibold text-accent-fg disabled:opacity-50"
      >
        {busyAction === "dispute" ? "…" : "Dispute"}
      </button>
      {error ? <span className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}
