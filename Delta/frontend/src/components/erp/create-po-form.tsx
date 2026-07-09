"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { createPurchaseOrderAction } from "@/app/(admin)/erp/actions";
import type { AssetView, VendorView } from "@/lib/types";

export function CreatePoForm({
  tenantId,
  vendors,
  assets,
}: {
  tenantId: string;
  vendors: VendorView[];
  assets: AssetView[];
}) {
  const router = useRouter();
  const [vendorId, setVendorId] = useState(vendors[0]?.vendor_id ?? "");
  const [assetId, setAssetId] = useState("");
  const [description, setDescription] = useState("");
  const [amountDollars, setAmountDollars] = useState("");
  const [requestedBy, setRequestedBy] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // `vendors` arrives as a prop from a server re-fetch (e.g. after adding a vendor
  // triggers router.refresh()) — the `useState` initializer above only runs once at
  // mount, so it goes stale the moment the list changes underneath it. Re-sync
  // whenever the selected id is no longer valid for the current list.
  useEffect(() => {
    if (!vendors.some((v) => v.vendor_id === vendorId)) {
      setVendorId(vendors[0]?.vendor_id ?? "");
    }
  }, [vendors, vendorId]);

  async function submit() {
    setError(null);
    if (!vendorId) {
      setError("Add a vendor first.");
      return;
    }
    if (description.trim().length === 0 || requestedBy.trim().length === 0) {
      setError("Description and requested-by are required.");
      return;
    }
    const amountMinorUnits = Math.round(Number(amountDollars) * 100);
    if (!Number.isFinite(amountMinorUnits) || amountMinorUnits < 0) {
      setError("Amount must be a non-negative number.");
      return;
    }
    setBusy(true);
    const result = await createPurchaseOrderAction({
      tenant_id: tenantId,
      vendor_id: vendorId,
      asset_id: assetId || undefined,
      description: description.trim(),
      amount_minor_units: amountMinorUnits,
      requested_by: requestedBy.trim(),
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setDescription("");
    setAmountDollars("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-5">
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
          value={assetId}
          onChange={(e) => setAssetId(e.target.value)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          <option value="">No asset link</option>
          {assets.map((a) => (
            <option key={a.asset_id} value={a.asset_id}>
              {a.name}
            </option>
          ))}
        </select>
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
          value={requestedBy}
          onChange={(e) => setRequestedBy(e.target.value)}
          placeholder="Requested by"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Creating…" : "Create PO"}
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
