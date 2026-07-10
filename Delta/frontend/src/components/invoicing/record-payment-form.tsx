"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { recordInvoicePaymentAction } from "@/app/(admin)/invoicing/actions";

/** Inline payment-recording control for an 'approved'/'partially_paid' invoice
 * (D-018). Rejected server-side (409/422) if the invoice isn't payable or this
 * would exceed its remaining balance — the atomic conditional-UPDATE race guard in
 * `delta.invoicing.store.try_record_payment` is the real backstop; this form just
 * surfaces whatever it decides. */
export function RecordPaymentForm({
  invoiceId,
  tenantId,
}: {
  invoiceId: string;
  tenantId: string;
}) {
  const router = useRouter();
  const [amountDollars, setAmountDollars] = useState("");
  const [recordedBy, setRecordedBy] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (recordedBy.trim().length === 0) {
      setError("Recorded-by required");
      return;
    }
    const amountMinorUnits = Math.round(Number(amountDollars) * 100);
    if (!Number.isFinite(amountMinorUnits) || amountMinorUnits <= 0) {
      setError("Amount must be a positive number.");
      return;
    }
    setBusy(true);
    const result = await recordInvoicePaymentAction(invoiceId, {
      tenant_id: tenantId,
      amount_minor_units: amountMinorUnits,
      paid_at: new Date().toISOString(),
      recorded_by: recordedBy.trim(),
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setAmountDollars("");
    router.refresh();
  }

  return (
    <div className="flex flex-wrap items-center gap-1">
      <input
        type="text"
        inputMode="decimal"
        value={amountDollars}
        onChange={(e) => setAmountDollars(e.target.value)}
        placeholder="Amount, USD"
        className="w-24 rounded-md border border-border bg-bg-inset px-1.5 py-1 text-xs text-fg"
      />
      <input
        type="text"
        value={recordedBy}
        onChange={(e) => setRecordedBy(e.target.value)}
        placeholder="recorded by"
        className="w-24 rounded-md border border-border bg-bg-inset px-1.5 py-1 text-xs text-fg"
      />
      <button
        type="button"
        onClick={submit}
        disabled={busy}
        className="rounded-md bg-accent px-2 py-1 text-xs font-semibold text-accent-fg disabled:opacity-50"
      >
        {busy ? "…" : "Record payment"}
      </button>
      {error ? <span className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}
