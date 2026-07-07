"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { decideAllocationAction } from "@/app/(admin)/allocations/actions";

/**
 * Approve/Reject controls for an allocation detail page (D-007). Each
 * decision requires an `actor` name and takes an optional note. The 409
 * "already decided" outcome is a real, expected result — rendered as a
 * distinct inline message with a refresh action, not a generic error toast.
 */
export function DecisionButtons({
  allocationId,
  tenantId,
  disabled,
}: {
  allocationId: string;
  tenantId: string;
  disabled: boolean;
}) {
  const router = useRouter();
  const [actor, setActor] = useState("");
  const [note, setNote] = useState("");
  const [busyAction, setBusyAction] = useState<"approve" | "reject" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);

  async function submit(action: "approve" | "reject") {
    setError(null);
    setConflict(false);
    if (actor.trim().length === 0) {
      setError("Actor name is required.");
      return;
    }
    setBusyAction(action);
    const result = await decideAllocationAction(allocationId, {
      tenant_id: tenantId,
      action,
      actor: actor.trim(),
      note: note.trim().length > 0 ? note.trim() : undefined,
    });
    setBusyAction(null);

    if (!result.ok) {
      if (result.status === 409) {
        setConflict(true);
      }
      setError(result.message);
      return;
    }

    setNote("");
    router.refresh();
  }

  return (
    <div className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
      <h2 className="font-mono text-sm font-semibold text-fg">Decision</h2>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label htmlFor="actor" className="block text-sm font-medium text-fg">
            Actor
          </label>
          <input
            id="actor"
            type="text"
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            disabled={disabled}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg disabled:opacity-50"
            placeholder="your name or operator id"
          />
        </div>
        <div>
          <label htmlFor="note" className="block text-sm font-medium text-fg">
            Note (optional)
          </label>
          <input
            id="note"
            type="text"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            disabled={disabled}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg disabled:opacity-50"
          />
        </div>
      </div>

      {error ? (
        <div role="alert" className="space-y-2 rounded-md border border-danger/40 bg-danger/10 p-3 text-sm text-danger">
          <p>{error}</p>
          {conflict ? (
            <button
              type="button"
              onClick={() => router.refresh()}
              className="rounded-md border border-danger/60 px-2 py-1 text-xs text-danger hover:bg-danger/10"
            >
              Refresh to see the outcome
            </button>
          ) : null}
        </div>
      ) : null}

      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => submit("approve")}
          disabled={disabled || busyAction !== null}
          className="rounded-md bg-ok px-3 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busyAction === "approve" ? "Approving…" : "Approve"}
        </button>
        <button
          type="button"
          onClick={() => submit("reject")}
          disabled={disabled || busyAction !== null}
          className="rounded-md bg-danger px-3 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busyAction === "reject" ? "Rejecting…" : "Reject"}
        </button>
      </div>
    </div>
  );
}
