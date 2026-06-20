import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { ErrorBanner } from "@/components/ui/error-banner";
import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";
import { formatTs } from "@/lib/format";
import type { AuditPageResponse } from "@/lib/types";

export default async function AuditPage({
  params,
  searchParams,
}: {
  params: { tenantId: string };
  searchParams: { after?: string };
}) {
  const after = Math.max(0, Number(searchParams.after ?? 0) || 0);

  let data: AuditPageResponse | null = null;
  let error: string | null = null;
  try {
    data = await adminApi.getAudit(params.tenantId, after, 50);
  } catch (e) {
    error = toFriendlyError(e).message;
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-sm text-fg-muted">Append-only audit log (keyset paginated).</p>
        {data ? (
          <Badge tone={data.chain_verified ? "ok" : "danger"}>
            {data.chain_verified ? "chain verified" : "chain INVALID"} · {data.chain_rows_checked} rows
          </Badge>
        ) : null}
      </div>

      {error ? <ErrorBanner message={error} /> : null}

      {data ? (
        <>
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-left text-sm">
              <thead className="bg-bg-raised text-xs uppercase text-fg-faint">
                <tr>
                  <th scope="col" className="px-3 py-2">Seq</th>
                  <th scope="col" className="px-3 py-2">Event</th>
                  <th scope="col" className="px-3 py-2">Action</th>
                  <th scope="col" className="px-3 py-2">Agent</th>
                  <th scope="col" className="px-3 py-2">Timestamp</th>
                  <th scope="col" className="px-3 py-2">Request ID</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {data.events.map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-bg-raised/50">
                    <td className="px-3 py-2 font-mono text-xs text-fg-muted">{ev.sequence_number}</td>
                    <td className="px-3 py-2 text-fg">{ev.event_type}</td>
                    <td className="px-3 py-2 text-fg-muted">{ev.action_taken || "—"}</td>
                    <td className="px-3 py-2 font-mono text-xs text-fg-muted">{ev.agent_id}</td>
                    <td className="px-3 py-2 font-mono text-xs text-fg-muted">{formatTs(ev.event_timestamp)}</td>
                    <td className="px-3 py-2 font-mono text-xs text-fg-faint">{ev.request_id}</td>
                  </tr>
                ))}
                {data.events.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-3 py-6 text-center text-sm text-fg-muted">
                      No audit events.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between">
            {after > 0 ? (
              <Link href={`/tenants/${params.tenantId}/audit`} className="text-sm text-accent hover:underline">
                ← First page
              </Link>
            ) : (
              <span />
            )}
            {data.next_cursor != null ? (
              <Link
                href={`/tenants/${params.tenantId}/audit?after=${data.next_cursor}`}
                className="text-sm text-accent hover:underline"
              >
                Next page →
              </Link>
            ) : (
              <span className="text-xs text-fg-faint">End of log</span>
            )}
          </div>
        </>
      ) : null}
    </div>
  );
}
