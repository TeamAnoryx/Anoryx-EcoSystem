"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createBudgetAction } from "@/app/(admin)/personal-finance/actions";
import type { PersonalBudgetCategory } from "@/lib/types";

const BUDGET_CATEGORIES: PersonalBudgetCategory[] = [
  "groceries",
  "rent",
  "utilities",
  "dining",
  "transport",
  "entertainment",
  "subscriptions",
  "healthcare",
  "other",
];

export function CreateBudgetForm({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [category, setCategory] = useState<PersonalBudgetCategory>("groceries");
  const [capDollars, setCapDollars] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    const capMinorUnits = Math.round(Number(capDollars) * 100);
    if (!Number.isFinite(capMinorUnits) || capMinorUnits <= 0) {
      setError("Cap must be a positive number.");
      return;
    }
    setBusy(true);
    const result = await createBudgetAction({
      tenant_id: tenantId,
      category,
      cap_minor_units: capMinorUnits,
      currency: "USD",
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setCapDollars("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value as PersonalBudgetCategory)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {BUDGET_CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <input
          type="text"
          inputMode="decimal"
          value={capDollars}
          onChange={(e) => setCapDollars(e.target.value)}
          placeholder="Monthly cap, USD"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Setting…" : "Set budget"}
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
