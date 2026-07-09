"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createStakeholderAction } from "@/app/(admin)/crm/actions";
import type { StakeholderRole } from "@/lib/types";

const ROLES: StakeholderRole[] = ["decision_maker", "influencer", "champion", "blocker", "unknown"];

export function AddStakeholderForm({
  clientId,
  tenantId,
}: {
  clientId: string;
  tenantId: string;
}) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [role, setRole] = useState<StakeholderRole>("unknown");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (name.trim().length === 0) {
      setError("Name is required.");
      return;
    }
    setBusy(true);
    const result = await createStakeholderAction(clientId, {
      tenant_id: tenantId,
      name: name.trim(),
      role,
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setName("");
    setRole("unknown");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Stakeholder name"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <select
          value={role}
          onChange={(e) => setRole(e.target.value as StakeholderRole)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Adding…" : "Add stakeholder"}
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
