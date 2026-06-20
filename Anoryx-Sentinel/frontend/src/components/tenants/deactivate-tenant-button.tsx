"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { ClientApiError, clientApi } from "@/lib/client-api";
import type { TenantResponse } from "@/lib/types";

export function DeactivateTenantButton({ tenantId, name }: { tenantId: string; name: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onClick() {
    if (!window.confirm(`Deactivate tenant "${name}"? Its keys will stop working.`)) return;
    setError(null);
    setBusy(true);
    try {
      await clientApi.post<TenantResponse>(`tenants/${encodeURIComponent(tenantId)}/deactivate`);
      router.refresh();
    } catch (err) {
      if (err instanceof ClientApiError && err.reauth) {
        router.replace("/login");
        return;
      }
      setError(err instanceof Error ? err.message : "Failed to deactivate.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="inline-flex items-center gap-2">
      <button
        type="button"
        onClick={onClick}
        disabled={busy}
        className="rounded-md border border-danger/40 px-2 py-1 text-xs text-danger hover:bg-danger/10 disabled:opacity-50"
      >
        {busy ? "…" : "Deactivate"}
      </button>
      {error ? (
        <span role="alert" className="text-xs text-danger">
          {error}
        </span>
      ) : null}
    </span>
  );
}
