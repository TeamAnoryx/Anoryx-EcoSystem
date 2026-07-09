"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { revokeAccessTokenAction } from "@/app/(admin)/rbac/actions";

export function RevokeTokenButton({ tokenId, tenantId }: { tokenId: string; tenantId: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function revoke() {
    setError(null);
    setBusy(true);
    const result = await revokeAccessTokenAction(tokenId, tenantId);
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    router.refresh();
  }

  return (
    <div className="flex items-center gap-1">
      <button
        type="button"
        onClick={revoke}
        disabled={busy}
        className="rounded-md border border-border px-2 py-1 text-xs text-danger hover:border-danger disabled:opacity-50"
      >
        {busy ? "Revoking…" : "Revoke"}
      </button>
      {error ? <span className="text-xs text-danger">{error}</span> : null}
    </div>
  );
}
