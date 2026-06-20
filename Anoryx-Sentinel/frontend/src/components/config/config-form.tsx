"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { ClientApiError, clientApi } from "@/lib/client-api";
import type { ConfigResponse, ConfigUpdateRequest } from "@/lib/types";

/**
 * View + guarded adjust of tenant config (ADR-0014 D6). Inputs mirror the table's
 * CHECK constraints: audit_mode ∈ {full, redacted}; team_rpm_limit > 0. Only
 * fields the operator changes are sent (the API does a partial update).
 */
export function ConfigForm({ tenantId, initial }: { tenantId: string; initial: ConfigResponse }) {
  const router = useRouter();
  const [classifier, setClassifier] = useState(initial.classifier_model_id ?? "");
  const [auditMode, setAuditMode] = useState(initial.audit_mode ?? "");
  const [rpm, setRpm] = useState(initial.team_rpm_limit != null ? String(initial.team_rpm_limit) : "");
  const [msg, setMsg] = useState<{ tone: "ok" | "danger"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setMsg(null);
    setBusy(true);

    const body: ConfigUpdateRequest = {};
    const cls = classifier.trim();
    if (cls !== (initial.classifier_model_id ?? "")) body.classifier_model_id = cls === "" ? null : cls;
    if (auditMode !== (initial.audit_mode ?? "")) {
      if (auditMode === "full" || auditMode === "redacted") body.audit_mode = auditMode;
    }
    const rpmInitial = initial.team_rpm_limit != null ? String(initial.team_rpm_limit) : "";
    if (rpm !== rpmInitial) body.team_rpm_limit = rpm === "" ? null : Number(rpm);

    if (Object.keys(body).length === 0) {
      setMsg({ tone: "ok", text: "No changes to save." });
      setBusy(false);
      return;
    }

    try {
      await clientApi.patch<ConfigResponse>(`tenants/${encodeURIComponent(tenantId)}/config`, body);
      setMsg({ tone: "ok", text: "Configuration updated." });
      router.refresh();
    } catch (err) {
      if (err instanceof ClientApiError && err.reauth) {
        router.replace("/login");
        return;
      }
      setMsg({ tone: "danger", text: err instanceof Error ? err.message : "Update failed." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="max-w-md space-y-4" noValidate>
      <div>
        <label htmlFor="c-classifier" className="block text-xs font-medium text-fg-muted">
          Classifier model ID (F-007)
        </label>
        <input
          id="c-classifier"
          value={classifier}
          onChange={(e) => setClassifier(e.target.value)}
          className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg"
          placeholder="(unset)"
        />
      </div>
      <div>
        <label htmlFor="c-audit" className="block text-xs font-medium text-fg-muted">
          Audit mode (F-009)
        </label>
        <select
          id="c-audit"
          value={auditMode}
          onChange={(e) => setAuditMode(e.target.value)}
          className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg"
        >
          <option value="">(unset — leave unchanged)</option>
          <option value="full">full</option>
          <option value="redacted">redacted</option>
        </select>
      </div>
      <div>
        <label htmlFor="c-rpm" className="block text-xs font-medium text-fg-muted">
          Team RPM limit (F-009)
        </label>
        <input
          id="c-rpm"
          type="number"
          min={1}
          value={rpm}
          onChange={(e) => setRpm(e.target.value)}
          className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg"
          placeholder="(unset)"
        />
      </div>
      <div className="flex items-center gap-3">
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-accent px-4 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50"
        >
          {busy ? "Saving…" : "Save changes"}
        </button>
        {msg ? (
          <span role="alert" className={`text-sm ${msg.tone === "ok" ? "text-ok" : "text-danger"}`}>
            {msg.text}
          </span>
        ) : null}
      </div>
    </form>
  );
}
