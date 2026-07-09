"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createAccessTokenAction } from "@/app/(admin)/rbac/actions";
import type { AccessRole } from "@/lib/types";

export function CreateTokenForm({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [role, setRole] = useState<AccessRole>("tenant_auditor");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revealedToken, setRevealedToken] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (name.trim().length === 0) {
      setError("Token name is required.");
      return;
    }
    setBusy(true);
    const result = await createAccessTokenAction({ tenant_id: tenantId, name: name.trim(), role });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setName("");
    setRevealedToken(result.data.token);
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      {revealedToken ? (
        <div className="space-y-2 rounded-md border border-accent bg-bg-raised p-3">
          <p className="text-sm font-medium text-fg">
            Token issued. Copy it now — it will not be shown again.
          </p>
          <code className="block break-all rounded-md bg-bg-inset px-2 py-1.5 text-xs text-fg">
            {revealedToken}
          </code>
          <button
            type="button"
            onClick={() => setRevealedToken(null)}
            className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:border-accent hover:text-fg"
          >
            I&apos;ve copied it
          </button>
        </div>
      ) : null}
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Token name (e.g. CI viewer key)"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <select
          value={role}
          onChange={(e) => setRole(e.target.value as AccessRole)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          <option value="tenant_auditor">tenant_auditor (view only)</option>
          <option value="tenant_admin">tenant_admin (full access)</option>
        </select>
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Issuing…" : "Issue token"}
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
