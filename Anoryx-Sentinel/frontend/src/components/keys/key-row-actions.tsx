"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { SecretReveal } from "@/components/keys/secret-reveal";
import { ClientApiError, clientApi } from "@/lib/client-api";
import type { KeyMintResponse, KeyResponse } from "@/lib/types";

export function KeyRowActions({
  tenantId,
  keyId,
  isActive,
}: {
  tenantId: string;
  keyId: string;
  isActive: boolean;
}) {
  const router = useRouter();
  const [secret, setSecret] = useState<string | null>(null);
  const [busy, setBusy] = useState<null | "rotate" | "revoke">(null);
  const [error, setError] = useState<string | null>(null);

  const base = `tenants/${encodeURIComponent(tenantId)}/keys/${encodeURIComponent(keyId)}`;

  function handleAuth(err: unknown): boolean {
    if (err instanceof ClientApiError && err.reauth) {
      router.replace("/login");
      return true;
    }
    setError(err instanceof Error ? err.message : "Action failed.");
    return false;
  }

  async function onRotate() {
    if (!window.confirm("Rotate this key? The current secret is revoked immediately.")) return;
    setError(null);
    setBusy("rotate");
    try {
      const res = await clientApi.post<KeyMintResponse>(`${base}/rotate`);
      setSecret(res.secret);
      router.refresh();
    } catch (err) {
      handleAuth(err);
    } finally {
      setBusy(null);
    }
  }

  async function onRevoke() {
    if (!window.confirm("Revoke this key? It stops working immediately.")) return;
    setError(null);
    setBusy("revoke");
    try {
      await clientApi.post<KeyResponse>(`${base}/revoke`);
      router.refresh();
    } catch (err) {
      handleAuth(err);
    } finally {
      setBusy(null);
    }
  }

  return (
    <span className="inline-flex items-center gap-2">
      {isActive ? (
        <>
          <button
            type="button"
            onClick={onRotate}
            disabled={busy !== null}
            className="rounded-md border border-border px-2 py-1 text-xs text-fg-muted hover:text-fg disabled:opacity-50"
          >
            {busy === "rotate" ? "…" : "Rotate"}
          </button>
          <button
            type="button"
            onClick={onRevoke}
            disabled={busy !== null}
            className="rounded-md border border-danger/40 px-2 py-1 text-xs text-danger hover:bg-danger/10 disabled:opacity-50"
          >
            {busy === "revoke" ? "…" : "Revoke"}
          </button>
        </>
      ) : (
        <span className="text-xs text-fg-faint">—</span>
      )}
      {error ? (
        <span role="alert" className="text-xs text-danger">
          {error}
        </span>
      ) : null}
      {secret ? <SecretReveal secret={secret} onClose={() => setSecret(null)} /> : null}
    </span>
  );
}
