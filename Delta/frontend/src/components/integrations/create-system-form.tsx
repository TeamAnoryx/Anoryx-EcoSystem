"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createExternalSystemAction } from "@/app/(admin)/integrations/actions";
import type { SystemType } from "@/lib/types";

const SYSTEM_TYPES: Array<{ label: string; value: SystemType }> = [
  { label: "Corporate ERP", value: "corporate_erp" },
  { label: "Procurement", value: "procurement" },
  { label: "Cloud cost", value: "cloud_cost" },
];

export function CreateSystemForm({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [systemType, setSystemType] = useState<SystemType>("corporate_erp");
  const [vendorLabel, setVendorLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (name.trim().length === 0 || vendorLabel.trim().length === 0) {
      setError("Name and vendor label are required.");
      return;
    }
    setBusy(true);
    const result = await createExternalSystemAction({
      tenant_id: tenantId,
      name: name.trim(),
      system_type: systemType,
      vendor_label: vendorLabel.trim(),
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setName("");
    setVendorLabel("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-4">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="System name (e.g. Corp NetSuite)"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <select
          value={systemType}
          onChange={(e) => setSystemType(e.target.value as SystemType)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {SYSTEM_TYPES.map((t) => (
            <option key={t.value} value={t.value}>
              {t.label}
            </option>
          ))}
        </select>
        <input
          type="text"
          value={vendorLabel}
          onChange={(e) => setVendorLabel(e.target.value)}
          placeholder="Vendor label (e.g. NetSuite, AWS)"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Registering…" : "Register system"}
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
