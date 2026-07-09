"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createAssetAction } from "@/app/(admin)/erp/actions";
import type { AssetCategory } from "@/lib/types";

const CATEGORIES: AssetCategory[] = [
  "equipment",
  "software_license",
  "furniture",
  "vehicle",
  "other",
];

export function CreateAssetForm({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [category, setCategory] = useState<AssetCategory>("equipment");
  const [costDollars, setCostDollars] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (name.trim().length === 0) {
      setError("Asset name is required.");
      return;
    }
    // Dollars -> integer minor units, never the other way (D-001's non-negotiable #3).
    const costMinorUnits =
      costDollars.trim().length > 0 ? Math.round(Number(costDollars) * 100) : undefined;
    if (costDollars.trim().length > 0 && !Number.isFinite(costMinorUnits)) {
      setError("Acquisition cost must be a number.");
      return;
    }
    setBusy(true);
    const result = await createAssetAction({
      tenant_id: tenantId,
      name: name.trim(),
      category,
      acquisition_cost_minor_units: costMinorUnits,
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setName("");
    setCostDollars("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-4">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Asset name"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value as AssetCategory)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <input
          type="text"
          inputMode="decimal"
          value={costDollars}
          onChange={(e) => setCostDollars(e.target.value)}
          placeholder="Cost, USD (optional)"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Adding…" : "Add asset"}
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
