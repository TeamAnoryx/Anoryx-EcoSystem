"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createInteractionAction } from "@/app/(admin)/crm/actions";
import type { InteractionType, StakeholderView } from "@/lib/types";

const TYPES: InteractionType[] = ["call", "email", "meeting", "note"];

export function AddInteractionForm({
  clientId,
  tenantId,
  stakeholders,
}: {
  clientId: string;
  tenantId: string;
  stakeholders: StakeholderView[];
}) {
  const router = useRouter();
  const [type, setType] = useState<InteractionType>("call");
  const [summary, setSummary] = useState("");
  const [createdBy, setCreatedBy] = useState("");
  const [stakeholderId, setStakeholderId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (summary.trim().length === 0 || createdBy.trim().length === 0) {
      setError("Summary and your name are required.");
      return;
    }
    setBusy(true);
    const result = await createInteractionAction(clientId, {
      tenant_id: tenantId,
      stakeholder_id: stakeholderId || undefined,
      interaction_type: type,
      occurred_at: new Date().toISOString(),
      summary: summary.trim(),
      created_by: createdBy.trim(),
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setSummary("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-4">
        <select
          value={type}
          onChange={(e) => setType(e.target.value as InteractionType)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <select
          value={stakeholderId}
          onChange={(e) => setStakeholderId(e.target.value)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          <option value="">No stakeholder tag</option>
          {stakeholders.map((s) => (
            <option key={s.stakeholder_id} value={s.stakeholder_id}>
              {s.name}
            </option>
          ))}
        </select>
        <input
          type="text"
          value={createdBy}
          onChange={(e) => setCreatedBy(e.target.value)}
          placeholder="Your name"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Logging…" : "Log interaction"}
        </button>
      </div>
      <input
        type="text"
        value={summary}
        onChange={(e) => setSummary(e.target.value)}
        placeholder="What happened?"
        className="w-full rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
      />
      {error ? (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      ) : null}
    </div>
  );
}
