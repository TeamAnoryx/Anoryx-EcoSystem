"use client";

import { useMemo, useState } from "react";

import { usePoll } from "@/components/dashboards/use-poll";
import { Badge } from "@/components/ui/badge";
import { ErrorBanner } from "@/components/ui/error-banner";
import { clientApi, ClientApiError } from "@/lib/client-api";
import { formatTs } from "@/lib/format";
import type { ModelInventoryItem, ModelInventoryListResponse } from "@/lib/types";

const POLL_MS = 15_000;

// ---------------------------------------------------------------------------
// Pure helpers — exported so render tests can assert without DOM wiring.
// ---------------------------------------------------------------------------

/**
 * Derive a stable, locale-independent retirement label for a model row.
 *
 * The label is fully honest about backend-enforcement:
 *  - "Retiring — usable until <date>"   when retire_at is set and now <= retire_at
 *  - "Retired — blocked since <date>"   when retire_at is set and now >  retire_at
 *    (the gateway denies this model fail-closed; say so)
 *  - "Approved"                          when approved and no retirement scheduled
 *  - "Pending" / "Denied"               for the other states
 *
 * `now` is passed in (never read from Date.now() here) so the helper is
 * deterministically testable without time-mocking.
 *
 * Date formatting uses ISO-derived strings (UTC, second precision) for
 * stability across locales and test environments.
 */
export function retirementLabel(item: ModelInventoryItem, now: Date): string {
  if (item.state === "pending") return "Pending";
  if (item.state === "denied") return "Denied";

  // state === "approved"
  if (!item.retire_at) return "Approved";

  const deadline = new Date(item.retire_at);
  // Stable, locale-independent format: "2026-07-01 12:00:00Z"
  const formatted = formatTs(item.retire_at);

  if (now <= deadline) {
    return `Retiring — usable until ${formatted}`;
  }
  return `Retired — blocked since ${formatted}`;
}

/** Badge tone for a model state label. */
function stateTone(item: ModelInventoryItem, now: Date): "ok" | "warn" | "danger" | "neutral" {
  if (item.state === "denied") return "danger";
  if (item.state === "pending") return "neutral";
  if (!item.retire_at) return "ok";
  const deadline = new Date(item.retire_at);
  return now <= deadline ? "warn" : "danger";
}

// ---------------------------------------------------------------------------
// Inline confirm state for mutations (avoids a full modal for each row).
// ---------------------------------------------------------------------------

type ConfirmKind = "approve" | "deny" | "retire" | "unretire";

interface ConfirmState {
  modelId: string;
  kind: ConfirmKind;
  retireAt?: string; // ISO Z string, set by the date-time picker for "retire"
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Model-governance panel (F-021).
 *
 * Polls GET tenants/{id}/models via the BFF (never Sentinel directly — R2).
 * Shows per-tenant model inventory with honest state labels and operator
 * approve/deny/retire/un-retire actions.
 *
 * Honesty constraints enforced here (ADR-0022/0024):
 *  - Retirement is backend-enforced — a model past its grace deadline is
 *    DENIED at the gateway fail-closed. The note in this panel states this.
 *  - State labels accurately reflect current backend state; no misleading
 *    "retiring" when retire_at is null.
 *  - All fields render as inert React text — no dangerouslySetInnerHTML.
 *  - Admin token stays server-side; this island uses clientApi BFF only.
 *
 * The parent passes `key={tenantId}` so a tenant switch remounts the island
 * and clears all prior-tenant state.
 */
export function ModelGovernancePanel({ tenantId }: { tenantId: string }) {
  const [confirm, setConfirm] = useState<ConfirmState | null>(null);
  const [actionError, setActionError] = useState<Record<string, string>>({});
  const [actionPending, setActionPending] = useState<Record<string, boolean>>({});
  // Remount key to force refetch after a mutation.
  const [refreshKey, setRefreshKey] = useState(0);

  const fetcher = useMemo(
    () => (signal: AbortSignal) =>
      clientApi.get<ModelInventoryListResponse>(
        `tenants/${encodeURIComponent(tenantId)}/models`,
        signal,
      ),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [tenantId, refreshKey],
  );

  const { data, error, loading } = usePoll<ModelInventoryListResponse>(
    fetcher,
    POLL_MS,
    `${tenantId}:${refreshKey}`,
  );

  const models = data?.models ?? [];

  // Fix 1 (MED): derive `now` from the poll data so it refreshes whenever a
  // new poll response arrives. If `now` were captured once at initial render,
  // a row whose retire_at passes while the panel stays mounted would keep
  // showing "Retiring" until an unrelated re-render. By depending on `data`,
  // `now` advances each time the poller delivers fresh state.
  const now = useMemo(() => new Date(), [data]);

  // -------------------------------------------------------------------------
  // Mutation helpers
  // -------------------------------------------------------------------------

  function clearConfirm() {
    setConfirm(null);
  }

  async function runAction(modelId: string, kind: ConfirmKind, retireAt?: string) {
    setActionPending((p) => ({ ...p, [modelId]: true }));
    setActionError((e) => {
      const next = { ...e };
      delete next[modelId];
      return next;
    });
    const tid = encodeURIComponent(tenantId);
    const mid = modelId;
    try {
      if (kind === "approve") {
        await clientApi.post<ModelInventoryItem>(`tenants/${tid}/models/approve`, {
          model_id: mid,
        });
      } else if (kind === "deny") {
        await clientApi.post<ModelInventoryItem>(`tenants/${tid}/models/deny`, {
          model_id: mid,
        });
      } else if (kind === "retire") {
        await clientApi.post<ModelInventoryItem>(`tenants/${tid}/models/retire`, {
          model_id: mid,
          retire_at: retireAt,
        });
      } else {
        await clientApi.post<ModelInventoryItem>(`tenants/${tid}/models/unretire`, {
          model_id: mid,
        });
      }
      setRefreshKey((k) => k + 1);
    } catch (err) {
      const msg =
        err instanceof ClientApiError
          ? err.message
          : "Action failed — please try again.";
      setActionError((e) => ({ ...e, [modelId]: msg }));
    } finally {
      setActionPending((p) => {
        const next = { ...p };
        delete next[modelId];
        return next;
      });
      clearConfirm();
    }
  }

  // -------------------------------------------------------------------------
  // Retire date-time picker validation helper
  // -------------------------------------------------------------------------

  function isRetireAtValid(iso: string | undefined): boolean {
    if (!iso) return false;
    const d = new Date(iso);
    return !Number.isNaN(d.getTime()) && d > now;
  }

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  return (
    <section
      className="space-y-3"
      aria-label="Model governance — per-tenant model inventory"
      data-testid="model-governance-panel"
    >
      {/* Section header + live indicator */}
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-medium text-fg-muted">Model inventory &amp; approval state</h3>
        <Badge tone="neutral">F-021 governance</Badge>
        <span className="inline-flex items-center gap-1 text-xs text-fg-faint">
          <span className="h-2 w-2 rounded-full bg-ok" aria-hidden="true" />
          live · polling {POLL_MS / 1000}s
        </span>
      </div>

      {/*
        Honesty note (ADR-0024): retirement is fail-closed backend enforcement.
        A model whose grace deadline has passed is DENIED at the gateway — the
        gateway does not let it through. This is not a reminder; it is the
        accurate description of what the system does.
      */}
      <div
        role="note"
        aria-label="Enforcement note"
        data-testid="model-governance-enforcement-note"
        className="rounded-md border border-border bg-bg-inset px-3 py-2 text-xs leading-relaxed text-fg-muted"
      >
        <span className="font-semibold">Enforcement: </span>
        Retirement is gateway-enforced fail-closed. Once a model&apos;s grace deadline
        passes, the gateway denies all requests for that model — regardless of UI state.
        Approve/Deny decisions take effect immediately via the model-approval policy
        (F-019, ADR-0022).
      </div>

      {error ? <ErrorBanner message={error} /> : null}

      {/* Model inventory table */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table
          className="w-full text-left text-sm"
          aria-label="Per-tenant model inventory"
        >
          <thead className="bg-bg-raised text-xs uppercase text-fg-faint">
            <tr>
              <th scope="col" className="px-3 py-2">Model ID</th>
              <th scope="col" className="px-3 py-2">Type</th>
              <th scope="col" className="px-3 py-2">State</th>
              <th scope="col" className="px-3 py-2">Approved by</th>
              <th scope="col" className="px-3 py-2">Approved at</th>
              <th scope="col" className="px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {models.map((m) => {
              const label = retirementLabel(m, now);
              const tone = stateTone(m, now);
              const pending = Boolean(actionPending[m.model_id]);
              const rowError = actionError[m.model_id] ?? null;
              const isConfirming = confirm?.modelId === m.model_id;

              return (
                <tr
                  key={m.model_id}
                  className="hover:bg-bg-raised/50"
                  data-testid="model-inventory-row"
                >
                  {/* Model ID */}
                  <td className="px-3 py-2 font-mono text-xs text-fg">
                    {m.model_id}
                  </td>

                  {/* Type */}
                  <td className="px-3 py-2 font-mono text-xs text-fg-muted">
                    {m.model_type === "fine_tune" ? "fine-tune" : "base"}
                  </td>

                  {/* State label — honest, never misleading */}
                  <td className="px-3 py-2" data-testid="model-state-label">
                    <Badge tone={tone}>{label}</Badge>
                  </td>

                  {/* Approved by */}
                  <td className="px-3 py-2 font-mono text-xs text-fg-muted">
                    {m.approved_by ?? "—"}
                  </td>

                  {/* Approved at */}
                  <td className="px-3 py-2 font-mono text-xs text-fg-faint">
                    {formatTs(m.approved_at)}
                  </td>

                  {/* Actions */}
                  <td className="px-3 py-2">
                    {rowError ? (
                      <p
                        role="alert"
                        className="mb-1 text-xs text-danger"
                        data-testid="model-action-error"
                      >
                        {rowError}
                      </p>
                    ) : null}

                    {!isConfirming ? (
                      <span className="inline-flex flex-wrap gap-1">
                        {/* Approve — available when pending or denied */}
                        {(m.state === "pending" || m.state === "denied") ? (
                          <button
                            type="button"
                            disabled={pending}
                            onClick={() => setConfirm({ modelId: m.model_id, kind: "approve" })}
                            className="rounded border border-ok/40 px-2 py-0.5 text-xs text-ok hover:bg-ok/10 disabled:opacity-50"
                            aria-label={`Approve model ${m.model_id}`}
                            data-testid="btn-approve"
                          >
                            Approve
                          </button>
                        ) : null}

                        {/* Deny — available when pending or approved */}
                        {(m.state === "pending" || m.state === "approved") ? (
                          <button
                            type="button"
                            disabled={pending}
                            onClick={() => setConfirm({ modelId: m.model_id, kind: "deny" })}
                            className="rounded border border-danger/40 px-2 py-0.5 text-xs text-danger hover:bg-danger/10 disabled:opacity-50"
                            aria-label={`Deny model ${m.model_id}`}
                            data-testid="btn-deny"
                          >
                            Deny
                          </button>
                        ) : null}

                        {/* Retire — only when approved and no retirement scheduled */}
                        {m.state === "approved" && !m.retire_at ? (
                          <button
                            type="button"
                            disabled={pending}
                            onClick={() =>
                              setConfirm({ modelId: m.model_id, kind: "retire", retireAt: "" })
                            }
                            className="rounded border border-warn/40 px-2 py-0.5 text-xs text-warn hover:bg-warn/10 disabled:opacity-50"
                            aria-label={`Schedule retirement for model ${m.model_id}`}
                            data-testid="btn-retire"
                          >
                            Retire
                          </button>
                        ) : null}

                        {/* Un-retire — only when approved and retirement is scheduled */}
                        {m.state === "approved" && m.retire_at ? (
                          <button
                            type="button"
                            disabled={pending}
                            onClick={() => setConfirm({ modelId: m.model_id, kind: "unretire" })}
                            className="rounded border border-border-strong px-2 py-0.5 text-xs text-fg-muted hover:bg-bg-raised disabled:opacity-50"
                            aria-label={`Cancel retirement for model ${m.model_id}`}
                            data-testid="btn-unretire"
                          >
                            Un-retire
                          </button>
                        ) : null}
                      </span>
                    ) : (
                      /* Inline confirm UI */
                      <div
                        className="flex flex-col gap-1"
                        data-testid="model-confirm-inline"
                      >
                        {confirm.kind === "retire" ? (
                          <>
                            <label
                              htmlFor={`retire-at-${m.model_id}`}
                              className="text-xs text-fg-muted"
                            >
                              {/*
                                Fix 2 (MED): datetime-local input uses the
                                browser's LOCAL timezone, not UTC. We convert
                                to UTC ISO before sending to the backend, but
                                the label must be honest about what the user
                                is entering so there is no ambiguity.
                              */}
                              Grace deadline (local time, sent as UTC):
                            </label>
                            <input
                              id={`retire-at-${m.model_id}`}
                              type="datetime-local"
                              value={confirm.retireAt ?? ""}
                              onChange={(e) =>
                                setConfirm((c) =>
                                  c ? { ...c, retireAt: e.target.value } : c,
                                )
                              }
                              className="rounded border border-border bg-bg-inset px-2 py-0.5 text-xs text-fg focus:outline-none focus:ring-1 focus:ring-warn"
                              aria-label="Retirement grace deadline (local time)"
                              data-testid="retire-at-input"
                            />
                            <p className="text-xs text-fg-faint">
                              Your browser&apos;s local time — converted to UTC
                              before submission. Must be a future instant.
                            </p>
                            <span className="flex gap-1">
                              <button
                                type="button"
                                disabled={
                                  pending ||
                                  !isRetireAtValid(
                                    confirm.retireAt
                                      ? new Date(confirm.retireAt).toISOString()
                                      : undefined,
                                  )
                                }
                                onClick={() => {
                                  if (!confirm.retireAt) return;
                                  // Convert local datetime-local value to ISO Z.
                                  const isoZ = new Date(confirm.retireAt).toISOString();
                                  void runAction(m.model_id, "retire", isoZ);
                                }}
                                className="rounded border border-warn/40 px-2 py-0.5 text-xs text-warn hover:bg-warn/10 disabled:opacity-50"
                                aria-label={`Confirm retirement for model ${m.model_id}`}
                                data-testid="btn-retire-confirm"
                              >
                                {pending ? "Retiring…" : "Confirm retire"}
                              </button>
                              <button
                                type="button"
                                onClick={clearConfirm}
                                className="rounded border border-border px-2 py-0.5 text-xs text-fg-muted hover:text-fg"
                                data-testid="btn-cancel"
                              >
                                Cancel
                              </button>
                            </span>
                          </>
                        ) : (
                          <>
                            <span className="text-xs text-fg-muted">
                              {confirm.kind === "approve" && "Approve this model?"}
                              {confirm.kind === "deny" && "Deny this model?"}
                              {confirm.kind === "unretire" && "Cancel retirement for this model?"}
                            </span>
                            <span className="flex gap-1">
                              <button
                                type="button"
                                disabled={pending}
                                onClick={() => void runAction(m.model_id, confirm.kind)}
                                className={
                                  confirm.kind === "approve"
                                    ? "rounded border border-ok/40 px-2 py-0.5 text-xs text-ok hover:bg-ok/10 disabled:opacity-50"
                                    : confirm.kind === "deny"
                                      ? "rounded border border-danger/40 px-2 py-0.5 text-xs text-danger hover:bg-danger/10 disabled:opacity-50"
                                      : "rounded border border-border-strong px-2 py-0.5 text-xs text-fg-muted hover:bg-bg-raised disabled:opacity-50"
                                }
                                aria-label={`Confirm ${confirm.kind} for model ${m.model_id}`}
                                data-testid="btn-confirm-action"
                              >
                                {pending ? "Processing…" : `Confirm ${confirm.kind}`}
                              </button>
                              <button
                                type="button"
                                onClick={clearConfirm}
                                className="rounded border border-border px-2 py-0.5 text-xs text-fg-muted hover:text-fg"
                                data-testid="btn-cancel"
                              >
                                Cancel
                              </button>
                            </span>
                          </>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}

            {models.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-6 text-center text-sm text-fg-muted"
                >
                  {loading
                    ? "Loading model inventory…"
                    : "No models in the inventory for this tenant."}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {/* Scope note */}
      <p className="text-xs text-fg-faint">
        Model inventory covers only models registered in this tenant&apos;s approval
        records. Enforcement is gateway-level: decisions take effect at the next
        request — no deployment or restart required.
      </p>
    </section>
  );
}
