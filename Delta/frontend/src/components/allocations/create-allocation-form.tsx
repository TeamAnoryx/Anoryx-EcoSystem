"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createAllocationAction } from "@/app/(admin)/allocations/actions";
import { formatMinorUnits } from "@/lib/money";
import type { AllocationTargetIn, BudgetPeriod, BudgetScope } from "@/lib/types";

/**
 * New-allocation form (D-007). All money fields are entered as INTEGER minor
 * units (cents) directly — never as a dollar amount converted client-side —
 * so no float ever touches the request body (non-negotiable #3). The dollar
 * preview next to each amount field is a pure, read-only display computed
 * from the same integer via `formatMinorUnits`; it is never read back into
 * the submitted value.
 */

interface TargetRow {
  key: number;
  scope: BudgetScope;
  team_id: string;
  project_id: string;
  agent_id: string;
  amount_minor_units: string;
}

let nextKey = 0;
function emptyRow(): TargetRow {
  return {
    key: nextKey++,
    scope: "team",
    team_id: "",
    project_id: "",
    agent_id: "",
    amount_minor_units: "",
  };
}

export function CreateAllocationForm({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [totalMinorUnits, setTotalMinorUnits] = useState("");
  const [currency, setCurrency] = useState("USD");
  const [period, setPeriod] = useState<BudgetPeriod>("monthly");
  const [requestedBy, setRequestedBy] = useState("");
  const [rows, setRows] = useState<TargetRow[]>([emptyRow()]);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function updateRow(key: number, patch: Partial<TargetRow>) {
    setRows((prev) => prev.map((r) => (r.key === key ? { ...r, ...patch } : r)));
  }

  function addRow() {
    setRows((prev) => [...prev, emptyRow()]);
  }

  function removeRow(key: number) {
    setRows((prev) => (prev.length > 1 ? prev.filter((r) => r.key !== key) : prev));
  }

  const totalNumber = Number.parseInt(totalMinorUnits, 10);
  const targetsSum = rows.reduce((sum, r) => {
    const n = Number.parseInt(r.amount_minor_units, 10);
    return sum + (Number.isFinite(n) ? n : 0);
  }, 0);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!Number.isInteger(totalNumber) || totalNumber < 0) {
      setError("Total (minor units) must be a non-negative whole number.");
      return;
    }
    if (requestedBy.trim().length === 0) {
      setError("Requested-by is required.");
      return;
    }
    if (!/^[A-Z]{3}$/.test(currency)) {
      setError("Currency must be a 3-letter ISO-4217 code (e.g. USD).");
      return;
    }

    const targets: AllocationTargetIn[] = [];
    for (const r of rows) {
      const amount = Number.parseInt(r.amount_minor_units, 10);
      if (!Number.isInteger(amount) || amount < 0) {
        setError("Every target amount must be a non-negative whole number of minor units.");
        return;
      }
      if (r.team_id.trim() === "" || r.project_id.trim() === "" || r.agent_id.trim() === "") {
        setError(
          "Every target row needs team_id, project_id, and agent_id — the API requires all three regardless of scope.",
        );
        return;
      }
      targets.push({
        scope: r.scope,
        team_id: r.team_id.trim(),
        project_id: r.project_id.trim(),
        agent_id: r.agent_id.trim(),
        amount_minor_units: amount,
      });
    }

    setSubmitting(true);
    const result = await createAllocationAction({
      tenant_id: tenantId,
      total_minor_units: totalNumber,
      currency,
      period,
      targets,
      requested_by: requestedBy.trim(),
    });
    setSubmitting(false);

    if (!result.ok) {
      // 422 reconciliation errors land here with the upstream detail string
      // ("targets don't sum to total_minor_units") shown inline, not a
      // generic toast.
      setError(result.message);
      return;
    }

    setTotalMinorUnits("");
    setRequestedBy("");
    setRows([emptyRow()]);
    router.push(`/allocations/${result.data.allocation_id}?tenant_id=${encodeURIComponent(tenantId)}`);
    router.refresh();
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4 rounded-lg border border-border bg-bg-raised p-4" noValidate>
      <h2 className="font-mono text-sm font-semibold text-fg">New allocation</h2>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <div>
          <label htmlFor="total" className="block text-sm font-medium text-fg">
            Total (minor units)
          </label>
          <input
            id="total"
            type="number"
            min={0}
            step={1}
            required
            value={totalMinorUnits}
            onChange={(e) => setTotalMinorUnits(e.target.value)}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg"
            placeholder="e.g. 10000 = $100.00"
          />
          {Number.isInteger(totalNumber) && totalNumber >= 0 ? (
            <p className="mt-1 text-xs text-fg-faint">≈ {formatMinorUnits(totalNumber, currency)}</p>
          ) : null}
        </div>

        <div>
          <label htmlFor="currency" className="block text-sm font-medium text-fg">
            Currency
          </label>
          <input
            id="currency"
            type="text"
            required
            maxLength={3}
            value={currency}
            onChange={(e) => setCurrency(e.target.value.toUpperCase())}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm uppercase text-fg"
            placeholder="USD"
          />
        </div>

        <div>
          <label htmlFor="period" className="block text-sm font-medium text-fg">
            Period
          </label>
          <select
            id="period"
            value={period}
            onChange={(e) => setPeriod(e.target.value as BudgetPeriod)}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg"
          >
            <option value="hourly">hourly</option>
            <option value="daily">daily</option>
            <option value="monthly">monthly</option>
          </select>
        </div>

        <div>
          <label htmlFor="requested-by" className="block text-sm font-medium text-fg">
            Requested by
          </label>
          <input
            id="requested-by"
            type="text"
            required
            value={requestedBy}
            onChange={(e) => setRequestedBy(e.target.value)}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg"
            placeholder="operator name or id"
          />
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-fg">Targets</h3>
          <p className="text-xs text-fg-faint">
            Sum: {targetsSum} minor units ({formatMinorUnits(targetsSum, currency)}) — must equal the total.
          </p>
        </div>

        <div className="mt-2 space-y-3">
          {rows.map((row) => (
            <div
              key={row.key}
              className="grid grid-cols-1 gap-2 rounded-md border border-border bg-bg-inset p-3 sm:grid-cols-6"
            >
              <select
                aria-label="Scope"
                value={row.scope}
                onChange={(e) => updateRow(row.key, { scope: e.target.value as BudgetScope })}
                className="rounded-md border border-border bg-bg px-2 py-1.5 text-sm text-fg"
              >
                <option value="tenant">tenant</option>
                <option value="team">team</option>
                <option value="project">project</option>
                <option value="agent">agent</option>
              </select>
              <input
                aria-label="Team id"
                placeholder="team_id (uuid)"
                value={row.team_id}
                onChange={(e) => updateRow(row.key, { team_id: e.target.value })}
                className="rounded-md border border-border bg-bg px-2 py-1.5 font-mono text-xs text-fg sm:col-span-1"
              />
              <input
                aria-label="Project id"
                placeholder="project_id (uuid)"
                value={row.project_id}
                onChange={(e) => updateRow(row.key, { project_id: e.target.value })}
                className="rounded-md border border-border bg-bg px-2 py-1.5 font-mono text-xs text-fg sm:col-span-1"
              />
              <input
                aria-label="Agent id"
                placeholder="agent_id (slug)"
                value={row.agent_id}
                onChange={(e) => updateRow(row.key, { agent_id: e.target.value })}
                className="rounded-md border border-border bg-bg px-2 py-1.5 font-mono text-xs text-fg sm:col-span-1"
              />
              <input
                aria-label="Amount (minor units)"
                type="number"
                min={0}
                step={1}
                placeholder="amount (minor units)"
                value={row.amount_minor_units}
                onChange={(e) => updateRow(row.key, { amount_minor_units: e.target.value })}
                className="rounded-md border border-border bg-bg px-2 py-1.5 text-sm text-fg"
              />
              <button
                type="button"
                onClick={() => removeRow(row.key)}
                disabled={rows.length === 1}
                className="rounded-md border border-border px-2 py-1.5 text-xs text-fg-muted hover:text-fg disabled:opacity-40"
              >
                Remove
              </button>
            </div>
          ))}
        </div>

        <button
          type="button"
          onClick={addRow}
          className="mt-2 rounded-md border border-border px-3 py-1.5 text-xs text-fg-muted hover:text-fg"
        >
          + Add target row
        </button>
      </div>

      {error ? (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}

      <button
        type="submit"
        disabled={submitting}
        className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50"
      >
        {submitting ? "Submitting…" : "Create allocation"}
      </button>
    </form>
  );
}
