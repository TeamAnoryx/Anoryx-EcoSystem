"use client";

import { useMemo } from "react";

import { usePoll } from "@/components/dashboards/use-poll";
import { Badge } from "@/components/ui/badge";
import { ErrorBanner } from "@/components/ui/error-banner";
import { clientApi } from "@/lib/client-api";
import { formatTs } from "@/lib/format";
import type { ShadowAiCandidate, ShadowAiCandidatesResponse } from "@/lib/types";

const POLL_MS = 15_000;

/**
 * Maps a confidence band to a badge tone.
 * "high" = warn (attention warranted), "medium" = warn (lighter), "low" = neutral.
 */
function bandTone(band: ShadowAiCandidate["confidence_band"]): "warn" | "neutral" {
  return band === "low" ? "neutral" : "warn";
}

/**
 * Shadow-AI candidate feed (F-018, ADR-0021 §8). Polls
 * `GET tenants/{id}/shadow-ai/candidates` through the existing BFF.
 *
 * Honesty constraints enforced here:
 *  - The `disclaimer` returned by the backend is rendered verbatim,
 *    prominently, and non-removably at the top of the panel (R1 / ADR-0021 §4).
 *  - Every candidate row carries the label "Candidate" and its confidence_band.
 *    Certainty language is prohibited — rows are review candidates, not findings
 *    (R3 / ADR-0021 §6).
 *  - All fields render as inert React text — no dangerouslySetInnerHTML (R5).
 *  - No admin token in the browser — clientApi hits /api/admin/* BFF only (R2).
 *
 * The parent passes `key={tenantId}` so a tenant switch remounts the island
 * and all accumulated state is cleared (R3 / ADR-0021 isolation).
 */
export function ShadowAiFeed({ tenantId }: { tenantId: string }) {
  const fetcher = useMemo(
    () => (signal: AbortSignal) =>
      clientApi.get<ShadowAiCandidatesResponse>(
        `tenants/${encodeURIComponent(tenantId)}/shadow-ai/candidates`,
        signal,
      ),
    [tenantId],
  );

  const { data, error, loading } = usePoll<ShadowAiCandidatesResponse>(
    fetcher,
    POLL_MS,
    tenantId,
  );

  const candidates = data?.candidates ?? [];
  const disclaimer = data?.disclaimer ?? null;

  return (
    <section
      className="space-y-3"
      aria-label="Shadow-AI candidate detection feed"
      data-testid="shadow-ai-feed"
    >
      {/* Section header + live indicator */}
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-medium text-fg-muted">Shadow-AI detection candidates</h3>
        <Badge tone="warn">detect-only · review candidates</Badge>
        <span className="inline-flex items-center gap-1 text-xs text-fg-faint">
          <span className="h-2 w-2 rounded-full bg-ok" aria-hidden="true" />
          live · polling {POLL_MS / 1000}s
        </span>
      </div>

      {/*
        R1 / ADR-0021 §4: Honesty boundary disclaimer.
        This block is non-removable — it renders the backend-supplied
        disclaimer verbatim (never a hardcoded alternative string). The
        backend returns the canonical HONESTY_DISCLAIMER constant from
        src/shadow_ai/constants.py on every response.
      */}
      {disclaimer !== null ? (
        <div
          role="note"
          aria-label="Detection scope disclaimer"
          data-testid="shadow-ai-disclaimer"
          className="rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs leading-relaxed text-warn"
        >
          <span className="font-semibold">Detection scope: </span>
          {disclaimer}
        </div>
      ) : (
        /*
          While the first poll is in-flight we show a stable placeholder so
          the layout does not shift. Once data arrives the real disclaimer
          replaces it. The placeholder text is conservative and honest.
        */
        <div
          role="note"
          aria-label="Detection scope disclaimer"
          data-testid="shadow-ai-disclaimer"
          className="rounded-md border border-border bg-bg-inset px-3 py-2 text-xs text-fg-faint"
        >
          {loading
            ? "Loading detection scope disclaimer…"
            : "Detection scope information unavailable."}
        </div>
      )}

      {error ? <ErrorBanner message={error} /> : null}

      {/* Candidate table */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-left text-sm" aria-label="Shadow-AI review candidates">
          <thead className="bg-bg-raised text-xs uppercase text-fg-faint">
            <tr>
              <th scope="col" className="px-3 py-2">Label</th>
              <th scope="col" className="px-3 py-2">Confidence</th>
              <th scope="col" className="px-3 py-2">Signals</th>
              <th scope="col" className="px-3 py-2">Team</th>
              <th scope="col" className="px-3 py-2">Project</th>
              <th scope="col" className="px-3 py-2">Endpoint</th>
              <th scope="col" className="px-3 py-2">Provider</th>
              <th scope="col" className="px-3 py-2">Calls</th>
              <th scope="col" className="px-3 py-2">First seen</th>
              <th scope="col" className="px-3 py-2">Last seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {candidates.map((c, idx) => (
              <tr
                key={`${c.team_id}-${c.project_id}-${c.endpoint}-${idx}`}
                className="hover:bg-bg-raised/50"
                data-testid="shadow-ai-candidate-row"
              >
                {/* R3: label is always "Candidate" — certainty language is prohibited */}
                <td className="px-3 py-2">
                  <Badge tone="neutral">Candidate</Badge>
                </td>
                <td className="px-3 py-2">
                  <Badge tone={bandTone(c.confidence_band)}>{c.confidence_band}</Badge>
                </td>
                <td className="px-3 py-2 font-mono text-xs text-fg-muted">
                  {c.fired_signals.join(", ")}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-fg-muted">{c.team_id}</td>
                <td className="px-3 py-2 font-mono text-xs text-fg-muted">{c.project_id}</td>
                <td className="px-3 py-2 font-mono text-xs text-fg-muted">{c.endpoint}</td>
                <td className="px-3 py-2 font-mono text-xs text-fg-muted">{c.provider}</td>
                <td className="px-3 py-2 font-mono text-xs text-fg-muted">{c.call_count}</td>
                <td className="px-3 py-2 font-mono text-xs text-fg-faint">
                  {formatTs(c.first_seen)}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-fg-faint">
                  {formatTs(c.last_seen)}
                </td>
              </tr>
            ))}
            {candidates.length === 0 ? (
              <tr>
                <td
                  colSpan={10}
                  className="px-3 py-6 text-center text-sm text-fg-muted"
                >
                  {loading
                    ? "Loading candidates…"
                    : "No shadow-AI review candidates for this tenant."}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {/* Scope note — risk reduction, not comprehensive coverage */}
      <p className="text-xs text-fg-faint">
        Detection covers only disallowed known-provider egress routed through Sentinel —
        risk reduction, not comprehensive shadow-AI coverage. Candidates require human
        review before any action is taken.
      </p>
    </section>
  );
}
