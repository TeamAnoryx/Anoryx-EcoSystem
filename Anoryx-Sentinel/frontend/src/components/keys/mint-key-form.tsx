"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { SecretReveal } from "@/components/keys/secret-reveal";
import { ClientApiError, clientApi } from "@/lib/client-api";
import type { KeyMintRequest, KeyMintResponse } from "@/lib/types";

const UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

export function MintKeyForm({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [form, setForm] = useState({ team_id: "", project_id: "", agent_id: "", label: "" });
  const [secret, setSecret] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function set<K extends keyof typeof form>(k: K, v: string) {
    setForm((f) => ({ ...f, [k]: v }));
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const body: KeyMintRequest = {
        team_id: form.team_id,
        project_id: form.project_id,
        agent_id: form.agent_id,
        label: form.label || null,
      };
      const res = await clientApi.post<KeyMintResponse>(
        `tenants/${encodeURIComponent(tenantId)}/keys`,
        body,
      );
      setSecret(res.secret);
      setForm({ team_id: "", project_id: "", agent_id: "", label: "" });
      router.refresh();
    } catch (err) {
      if (err instanceof ClientApiError && err.reauth) {
        router.replace("/login");
        return;
      }
      setError(err instanceof Error ? err.message : "Failed to mint key.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <form onSubmit={onSubmit} className="grid grid-cols-1 gap-3 sm:grid-cols-2" noValidate>
        <Field id="k-team" label="Team ID (UUID)" value={form.team_id} onChange={(v) => set("team_id", v)} pattern={UUID} required mono />
        <Field id="k-project" label="Project ID (UUID)" value={form.project_id} onChange={(v) => set("project_id", v)} pattern={UUID} required mono />
        <Field id="k-agent" label="Agent ID (slug)" value={form.agent_id} onChange={(v) => set("agent_id", v)} pattern="[a-z0-9]+(-[a-z0-9]+)*" required mono />
        <Field id="k-label" label="Label (optional)" value={form.label} onChange={(v) => set("label", v)} />
        <div className="sm:col-span-2">
          <button
            type="submit"
            disabled={busy}
            className="rounded-md bg-accent px-4 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50"
          >
            {busy ? "Minting…" : "Mint key"}
          </button>
          {error ? (
            <p role="alert" className="mt-2 text-sm text-danger">
              {error}
            </p>
          ) : null}
        </div>
      </form>
      {secret ? <SecretReveal secret={secret} onClose={() => setSecret(null)} /> : null}
    </>
  );
}

function Field({
  id,
  label,
  value,
  onChange,
  pattern,
  required,
  mono,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  pattern?: string;
  required?: boolean;
  mono?: boolean;
}) {
  return (
    <div>
      <label htmlFor={id} className="block text-xs font-medium text-fg-muted">
        {label}
      </label>
      <input
        id={id}
        value={value}
        required={required}
        pattern={pattern}
        onChange={(e) => onChange(e.target.value)}
        className={`mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg ${
          mono ? "font-mono" : ""
        }`}
      />
    </div>
  );
}
