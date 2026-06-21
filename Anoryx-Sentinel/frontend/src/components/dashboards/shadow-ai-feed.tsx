import { Badge } from "@/components/ui/badge";
import { formatTs } from "@/lib/format";
import type { AuditEventResponse } from "@/lib/types";

/**
 * Shadow-AI detection feed (F-013 governance panel). Renders shadow-AI egress
 * events from the audit log. PROGRESSIVE + HONEST (R6): detection is
 * detect-and-audit only (F-007 egress monitor — no separate F-018 task remains),
 * and the audit projection omits detected_endpoint/provider, so the feed shows
 * occurrence (type/team/agent/time), not endpoint detail. Labeled accordingly.
 * Inert text only (R5).
 */
export function ShadowAiFeed({ events }: { events: AuditEventResponse[] }) {
  return (
    <section className="space-y-2" aria-label="Shadow-AI detection feed">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-medium text-fg-muted">Shadow-AI detections</h3>
        <Badge tone="warn">progressive · detect-only</Badge>
      </div>
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-bg-raised text-xs uppercase text-fg-faint">
            <tr>
              <th scope="col" className="px-3 py-2">Seq</th>
              <th scope="col" className="px-3 py-2">Event</th>
              <th scope="col" className="px-3 py-2">Team</th>
              <th scope="col" className="px-3 py-2">Agent</th>
              <th scope="col" className="px-3 py-2">Timestamp</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {events.map((ev) => (
              <tr key={ev.event_id} className="hover:bg-bg-raised/50">
                <td className="px-3 py-2 font-mono text-xs text-fg-muted">{ev.sequence_number}</td>
                <td className="px-3 py-2 text-fg">{ev.event_type}</td>
                <td className="px-3 py-2 font-mono text-xs text-fg-muted">{ev.team_id}</td>
                <td className="px-3 py-2 font-mono text-xs text-fg-muted">{ev.agent_id}</td>
                <td className="px-3 py-2 font-mono text-xs text-fg-faint">
                  {formatTs(ev.event_timestamp)}
                </td>
              </tr>
            ))}
            {events.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-sm text-fg-muted">
                  No shadow-AI detections in the loaded window.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-fg-faint">
        Endpoint/provider detail is not shown — the audit projection omits those fields (deferred,
        see ADR-0016).
      </p>
    </section>
  );
}
