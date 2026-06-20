"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { ClientApiError, clientApi } from "@/lib/client-api";
import type { TenantResponse } from "@/lib/types";

export function CreateTenantForm() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await clientApi.post<TenantResponse>("tenants", {
        name,
        display_name: displayName || null,
      });
      setName("");
      setDisplayName("");
      router.refresh();
    } catch (err) {
      if (err instanceof ClientApiError && err.reauth) {
        router.replace("/login");
        return;
      }
      setError(err instanceof Error ? err.message : "Failed to create tenant.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="flex flex-wrap items-end gap-3" noValidate>
      <div>
        <label htmlFor="t-name" className="block text-xs font-medium text-fg-muted">
          Name
        </label>
        <input
          id="t-name"
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
          title="Letters, digits, dot, underscore, dash; must start alphanumeric."
          className="mt-1 w-56 rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg"
          placeholder="acme-corp"
        />
      </div>
      <div>
        <label htmlFor="t-display" className="block text-xs font-medium text-fg-muted">
          Display name (optional)
        </label>
        <input
          id="t-display"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          className="mt-1 w-56 rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg"
          placeholder="Acme Corporation"
        />
      </div>
      <button
        type="submit"
        disabled={busy || name.length === 0}
        className="rounded-md bg-accent px-4 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50"
      >
        {busy ? "Creating…" : "Create tenant"}
      </button>
      {error ? (
        <p role="alert" className="w-full text-sm text-danger">
          {error}
        </p>
      ) : null}
    </form>
  );
}
