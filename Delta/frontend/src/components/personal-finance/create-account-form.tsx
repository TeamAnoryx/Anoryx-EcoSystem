"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createAccountAction } from "@/app/(admin)/personal-finance/actions";
import type { PersonalAccountType } from "@/lib/types";

const ACCOUNT_TYPES: PersonalAccountType[] = [
  "checking",
  "savings",
  "credit_card",
  "cash",
  "investment",
];

export function CreateAccountForm({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [type, setType] = useState<PersonalAccountType>("checking");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (name.trim().length === 0) {
      setError("Account name is required.");
      return;
    }
    setBusy(true);
    const result = await createAccountAction({
      tenant_id: tenantId,
      type,
      currency: "USD",
      name: name.trim(),
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setName("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <select
          value={type}
          onChange={(e) => setType(e.target.value as PersonalAccountType)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {ACCOUNT_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Account name (e.g. Main checking)"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <button
          type="button"
          onClick={submit}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Adding…" : "Add account"}
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
