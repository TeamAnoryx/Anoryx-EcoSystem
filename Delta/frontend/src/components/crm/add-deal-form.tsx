"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createDealAction } from "@/app/(admin)/crm/actions";

export function AddDealForm({ clientId, tenantId }: { clientId: string; tenantId: string }) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [valueDollars, setValueDollars] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (name.trim().length === 0) {
      setError("Deal name is required.");
      return;
    }
    // Dollars -> integer minor units, never the other way (D-001's non-negotiable #3).
    const valueMinorUnits =
      valueDollars.trim().length > 0 ? Math.round(Number(valueDollars) * 100) : undefined;
    if (valueDollars.trim().length > 0 && !Number.isFinite(valueMinorUnits)) {
      setError("Deal value must be a number.");
      return;
    }
    setBusy(true);
    const result = await createDealAction(clientId, {
      tenant_id: tenantId,
      name: name.trim(),
      value_minor_units: valueMinorUnits,
    });
    setBusy(false);

    if (!result.ok) {
      setError(result.message);
      return;
    }
    setName("");
    setValueDollars("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Deal name"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <input
          type="text"
          inputMode="decimal"
          value={valueDollars}
          onChange={(e) => setValueDollars(e.target.value)}
          placeholder="Value, USD (optional)"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Adding…" : "Add deal"}
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
