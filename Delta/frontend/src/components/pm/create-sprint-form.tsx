"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createSprintAction } from "@/app/(admin)/pm/actions";

export function CreateSprintForm({ tenantId, projectId }: { tenantId: string; projectId: string }) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (name.trim().length === 0) {
      setError("Sprint name is required.");
      return;
    }
    if (!startDate || !endDate) {
      setError("Start and end dates are required.");
      return;
    }
    setBusy(true);
    const result = await createSprintAction({
      tenant_id: tenantId,
      project_id: projectId,
      name: name.trim(),
      start_date: new Date(startDate).toISOString(),
      end_date: new Date(endDate).toISOString(),
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setName("");
    setStartDate("");
    setEndDate("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-4">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Sprint name"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <input
          type="date"
          value={startDate}
          onChange={(e) => setStartDate(e.target.value)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <input
          type="date"
          value={endDate}
          onChange={(e) => setEndDate(e.target.value)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Creating…" : "Add sprint"}
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
