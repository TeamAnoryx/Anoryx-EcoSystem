"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { createClientAction } from "@/app/(admin)/crm/actions";

/** Inline "create client" form for the /crm list page (D-013). On success,
 * navigates straight to the new client's detail page. */
export function CreateClientForm({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [contactName, setContactName] = useState("");
  const [contactEmail, setContactEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    if (name.trim().length === 0) {
      setError("Client name is required.");
      return;
    }
    setBusy(true);
    const result = await createClientAction({
      tenant_id: tenantId,
      name: name.trim(),
      primary_contact_name: contactName.trim() || undefined,
      primary_contact_email: contactEmail.trim() || undefined,
    });
    setBusy(false);

    if (!result.ok) {
      setError(result.message);
      return;
    }
    router.push(`/crm/${result.data.client_id}?tenant_id=${encodeURIComponent(tenantId)}`);
  }

  return (
    <div className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
      <h2 className="font-mono text-sm font-semibold text-fg">New client</h2>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div>
          <label htmlFor="client-name" className="block text-sm font-medium text-fg">
            Name
          </label>
          <input
            id="client-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg"
            placeholder="Acme Corp"
          />
        </div>
        <div>
          <label htmlFor="client-contact-name" className="block text-sm font-medium text-fg">
            Primary contact (optional)
          </label>
          <input
            id="client-contact-name"
            type="text"
            value={contactName}
            onChange={(e) => setContactName(e.target.value)}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg"
          />
        </div>
        <div>
          <label htmlFor="client-contact-email" className="block text-sm font-medium text-fg">
            Contact email (optional)
          </label>
          <input
            id="client-contact-email"
            type="email"
            value={contactEmail}
            onChange={(e) => setContactEmail(e.target.value)}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg"
          />
        </div>
      </div>

      {error ? (
        <p role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}

      <button
        type="button"
        onClick={submit}
        disabled={busy}
        className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50"
      >
        {busy ? "Creating…" : "Create client"}
      </button>
    </div>
  );
}
