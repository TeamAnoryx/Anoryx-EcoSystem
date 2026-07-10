"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { runSyncAction } from "@/app/(admin)/integrations/actions";
import type { SyncLineItemInput } from "@/lib/types";

type ReferenceType = "none" | "po" | "invoice";

interface Row {
  externalReference: string;
  amountDollars: string;
  referenceType: ReferenceType;
  referenceId: string;
}

function emptyRow(): Row {
  return { externalReference: "", amountDollars: "", referenceType: "none", referenceId: "" };
}

/** Manually-triggered sync ingestion (D-019). Each row simulates one line item a
 * real NetSuite/SAP/AWS-Cost-Explorer/... connector would report — the reconciliation
 * logic here is real; only the live external fetch is deferred (ADR-0019 §3). */
export function RunSyncForm({ tenantId, systemId }: { tenantId: string; systemId: string }) {
  const router = useRouter();
  const [rows, setRows] = useState<Row[]>([emptyRow()]);
  const [triggeredBy, setTriggeredBy] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function updateRow(index: number, patch: Partial<Row>) {
    setRows((prev) => prev.map((r, i) => (i === index ? { ...r, ...patch } : r)));
  }

  function addRow() {
    setRows((prev) => [...prev, emptyRow()]);
  }

  function removeRow(index: number) {
    setRows((prev) => (prev.length === 1 ? prev : prev.filter((_, i) => i !== index)));
  }

  async function submit() {
    setError(null);
    if (triggeredBy.trim().length === 0) {
      setError("Triggered-by is required.");
      return;
    }
    const lineItems: SyncLineItemInput[] = [];
    for (const row of rows) {
      if (row.externalReference.trim().length === 0) {
        setError("Every row needs an external reference.");
        return;
      }
      const amountMinorUnits = Math.round(Number(row.amountDollars) * 100);
      if (!Number.isFinite(amountMinorUnits) || amountMinorUnits < 0) {
        setError("Every row's amount must be a non-negative number.");
        return;
      }
      if (row.referenceType !== "none" && row.referenceId.trim().length === 0) {
        setError("A reference type of PO/invoice needs a reference ID, or set it to none.");
        return;
      }
      lineItems.push({
        external_reference: row.externalReference.trim(),
        amount_minor_units: amountMinorUnits,
        currency: "USD",
        po_id: row.referenceType === "po" ? row.referenceId.trim() : undefined,
        invoice_id: row.referenceType === "invoice" ? row.referenceId.trim() : undefined,
      });
    }
    setBusy(true);
    const result = await runSyncAction(systemId, {
      tenant_id: tenantId,
      triggered_by: triggeredBy.trim(),
      line_items: lineItems,
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setRows([emptyRow()]);
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <p className="text-xs text-fg-muted">
        Each row simulates one line item a real connector would report. Leave the
        reference as &quot;None&quot; for a line item with no Delta-side counterpart
        (e.g. a cloud-cost charge).
      </p>
      {rows.map((row, i) => (
        <div key={i} className="grid grid-cols-1 gap-2 sm:grid-cols-5">
          <input
            type="text"
            value={row.externalReference}
            onChange={(e) => updateRow(i, { externalReference: e.target.value })}
            placeholder="External reference"
            className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
          />
          <input
            type="text"
            inputMode="decimal"
            value={row.amountDollars}
            onChange={(e) => updateRow(i, { amountDollars: e.target.value })}
            placeholder="Amount, USD"
            className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
          />
          <select
            value={row.referenceType}
            onChange={(e) => updateRow(i, { referenceType: e.target.value as ReferenceType })}
            className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
          >
            <option value="none">No Delta reference</option>
            <option value="po">Purchase order</option>
            <option value="invoice">Invoice</option>
          </select>
          <input
            type="text"
            value={row.referenceId}
            onChange={(e) => updateRow(i, { referenceId: e.target.value })}
            placeholder="Reference ID"
            disabled={row.referenceType === "none"}
            className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg disabled:opacity-40"
          />
          <button
            type="button"
            onClick={() => removeRow(i)}
            disabled={rows.length === 1}
            className="rounded-md border border-border px-2 py-1.5 text-xs text-fg-muted disabled:opacity-40"
          >
            Remove
          </button>
        </div>
      ))}
      <button
        type="button"
        onClick={addRow}
        className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:text-fg"
      >
        + Add line item
      </button>
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="text"
          value={triggeredBy}
          onChange={(e) => setTriggeredBy(e.target.value)}
          placeholder="Triggered by"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Syncing…" : "Run sync"}
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
