"use client";

import { useEffect, useMemo, useRef, useState } from "react";

import { BreakdownBars } from "@/components/dashboards/breakdown-bars";
import { usePoll } from "@/components/dashboards/use-poll";
import { ErrorBanner } from "@/components/ui/error-banner";
import { clientApi } from "@/lib/client-api";
import { aggregateByTeam, aggregateByType, filterSecurityEvents } from "@/lib/dashboards";
import { formatTs } from "@/lib/format";
import type { AuditEventResponse, AuditPageResponse } from "@/lib/types";

const POLL_MS = 5000;
const MAX_EVENTS = 200;

/**
 * Live security event feed (F-013 D1 — polling). Seeds with the server-fetched
 * recent tail, then polls the audit read through the BFF for events appended
 * since the last seen sequence (R1). The parent passes `key={tenantId}` so a
 * tenant switch remounts this island and all accumulated state is dropped (R3).
 *
 * All event fields render as inert React text — no dangerouslySetInnerHTML — so
 * a crafted payload string cannot execute (R5, vector 5). The audit projection
 * is metadata-only, so the feed shows type/action/scope/time, not payload.
 */
export function SecurityFeed({
  tenantId,
  initialEvents,
  initialLastSequence,
}: {
  tenantId: string;
  initialEvents: AuditEventResponse[];
  initialLastSequence: number;
}) {
  const [events, setEvents] = useState<AuditEventResponse[]>(initialEvents);
  const cursor = useRef(initialLastSequence);

  const fetcher = (signal: AbortSignal) =>
    clientApi.get<AuditPageResponse>(
      `tenants/${encodeURIComponent(tenantId)}/audit?after_sequence=${cursor.current}&limit=${MAX_EVENTS}`,
      signal,
    );
  const { data, error } = usePoll<AuditPageResponse>(fetcher, POLL_MS, tenantId);

  useEffect(() => {
    if (!data || data.events.length === 0) return;
    const maxSeq = data.events[data.events.length - 1].sequence_number;
    cursor.current = Math.max(cursor.current, maxSeq);
    setEvents((prev) => [...prev, ...data.events].slice(-MAX_EVENTS));
  }, [data]);

  const securityEvents = useMemo(() => filterSecurityEvents(events), [events]);
  const newestFirst = useMemo(() => [...securityEvents].reverse(), [securityEvents]);
  const teamBuckets = useMemo(() => aggregateByTeam(securityEvents), [securityEvents]);
  const typeBuckets = useMemo(() => aggregateByType(securityEvents), [securityEvents]);

  return (
    <div className="space-y-6">
      {error ? <ErrorBanner message={error} /> : null}

      <div className="grid gap-6 lg:grid-cols-2">
        <BreakdownBars
          buckets={teamBuckets}
          label="By team (loaded window)"
          mono
          emptyText="No security events in the loaded window."
        />
        <BreakdownBars
          buckets={typeBuckets}
          label="By event type (loaded window)"
          emptyText="No security events in the loaded window."
        />
      </div>

      <section aria-label="Security event feed" className="space-y-2">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-medium text-fg-muted">Recent security events</h3>
          <span className="inline-flex items-center gap-1 text-xs text-fg-faint">
            <span className="h-2 w-2 rounded-full bg-ok" aria-hidden="true" />
            live · polling {POLL_MS / 1000}s
          </span>
        </div>
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-raised text-xs uppercase text-fg-faint">
              <tr>
                <th scope="col" className="px-3 py-2">Seq</th>
                <th scope="col" className="px-3 py-2">Event</th>
                <th scope="col" className="px-3 py-2">Action</th>
                <th scope="col" className="px-3 py-2">Team</th>
                <th scope="col" className="px-3 py-2">Agent</th>
                <th scope="col" className="px-3 py-2">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {newestFirst.map((ev) => (
                <tr key={ev.event_id} className="hover:bg-bg-raised/50">
                  <td className="px-3 py-2 font-mono text-xs text-fg-muted">{ev.sequence_number}</td>
                  <td className="px-3 py-2 text-fg">{ev.event_type}</td>
                  <td className="px-3 py-2 text-fg-muted">{ev.action_taken || "—"}</td>
                  <td className="px-3 py-2 font-mono text-xs text-fg-muted">{ev.team_id}</td>
                  <td className="px-3 py-2 font-mono text-xs text-fg-muted">{ev.agent_id}</td>
                  <td className="px-3 py-2 font-mono text-xs text-fg-faint">
                    {formatTs(ev.event_timestamp)}
                  </td>
                </tr>
              ))}
              {newestFirst.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-3 py-6 text-center text-sm text-fg-muted">
                    No security events in the loaded window.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-fg-faint">
          Forward-only audit read: shows the most recent loaded events and live-appends new ones.
          Per-model breakdown is not available — the audit projection carries no model field
          (deferred, see ADR-0016).
        </p>
      </section>
    </div>
  );
}
