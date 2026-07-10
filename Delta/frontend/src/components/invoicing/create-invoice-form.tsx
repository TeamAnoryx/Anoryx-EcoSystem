"use client";

import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { createInvoiceAction } from "@/app/(admin)/invoicing/actions";
import type { PurchaseOrderView, VendorView } from "@/lib/types";

export function CreateInvoiceForm({
  tenantId,
  vendors,
  approvedPurchaseOrders,
}: {
  tenantId: string;
  vendors: VendorView[];
  approvedPurchaseOrders: PurchaseOrderView[];
}) {
  const router = useRouter();
  const [vendorId, setVendorId] = useState(vendors[0]?.vendor_id ?? "");
  const [poId, setPoId] = useState("");
  const [milestoneTaskId, setMilestoneTaskId] = useState("");
  const [invoiceNumber, setInvoiceNumber] = useState("");
  const [description, setDescription] = useState("");
  const [amountDollars, setAmountDollars] = useState("");
  const [submittedBy, setSubmittedBy] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const posForVendor = useMemo(
    () => approvedPurchaseOrders.filter((po) => po.vendor_id === vendorId),
    [approvedPurchaseOrders, vendorId],
  );

  // `vendors`/`approvedPurchaseOrders` arrive as props from a server re-fetch — the
  // `useState` initializers only run once at mount, so they go stale the moment the
  // lists change underneath them (mirrors erp/create-po-form.tsx's identical fix).
  useEffect(() => {
    if (!vendors.some((v) => v.vendor_id === vendorId)) {
      setVendorId(vendors[0]?.vendor_id ?? "");
    }
  }, [vendors, vendorId]);

  useEffect(() => {
    if (!posForVendor.some((po) => po.po_id === poId)) {
      setPoId(posForVendor[0]?.po_id ?? "");
    }
  }, [posForVendor, poId]);

  async function submit() {
    setError(null);
    if (!vendorId || !poId) {
      setError("Select a vendor with at least one approved purchase order first.");
      return;
    }
    if (invoiceNumber.trim().length === 0 || description.trim().length === 0 || submittedBy.trim().length === 0) {
      setError("Invoice number, description, and submitted-by are required.");
      return;
    }
    const amountMinorUnits = Math.round(Number(amountDollars) * 100);
    if (!Number.isFinite(amountMinorUnits) || amountMinorUnits < 0) {
      setError("Amount must be a non-negative number.");
      return;
    }
    setBusy(true);
    const result = await createInvoiceAction({
      tenant_id: tenantId,
      vendor_id: vendorId,
      po_id: poId,
      milestone_task_id: milestoneTaskId.trim() || undefined,
      invoice_number: invoiceNumber.trim(),
      description: description.trim(),
      amount_minor_units: amountMinorUnits,
      submitted_by: submittedBy.trim(),
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setInvoiceNumber("");
    setDescription("");
    setAmountDollars("");
    setMilestoneTaskId("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <select
          value={vendorId}
          onChange={(e) => setVendorId(e.target.value)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {vendors.length === 0 ? <option value="">No vendors yet</option> : null}
          {vendors.map((v) => (
            <option key={v.vendor_id} value={v.vendor_id}>
              {v.name}
            </option>
          ))}
        </select>
        <select
          value={poId}
          onChange={(e) => setPoId(e.target.value)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {posForVendor.length === 0 ? (
            <option value="">No approved POs for this vendor</option>
          ) : null}
          {posForVendor.map((po) => (
            <option key={po.po_id} value={po.po_id}>
              {po.description} ({(po.amount_minor_units / 100).toFixed(2)} {po.currency})
            </option>
          ))}
        </select>
        <input
          type="text"
          value={milestoneTaskId}
          onChange={(e) => setMilestoneTaskId(e.target.value)}
          placeholder="Milestone task ID (optional, must be 'done')"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-4">
        <input
          type="text"
          value={invoiceNumber}
          onChange={(e) => setInvoiceNumber(e.target.value)}
          placeholder="Invoice number"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <input
          type="text"
          inputMode="decimal"
          value={amountDollars}
          onChange={(e) => setAmountDollars(e.target.value)}
          placeholder="Amount, USD"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <input
          type="text"
          value={submittedBy}
          onChange={(e) => setSubmittedBy(e.target.value)}
          placeholder="Submitted by"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Submitting…" : "Submit invoice"}
        </button>
      </div>
      <input
        type="text"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        placeholder="Description"
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
