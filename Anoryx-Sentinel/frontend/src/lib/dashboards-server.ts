import "server-only";

import { adminApi } from "@/lib/admin-client";
import type { AuditEventResponse } from "@/lib/types";

/**
 * Server-side audit-feed bootstrap for F-013 (ADR-0016). The admin audit read is
 * a FORWARD-ONLY ascending keyset (sequence_number > after, ASC) with no tail
 * endpoint, so to surface the MOST RECENT events we page forward following
 * next_cursor up to a BOUNDED page cap and keep the tail slice. The bound
 * prevents a runaway loop on a large log; if the log exceeds the cap the oldest
 * events beyond the window are not shown here (operators use the full audit
 * viewer). This is client-of-the-admin-API orchestration — no backend change.
 */

const PAGE_LIMIT = 200; // per the admin audit-read hard max
const PAGE_CAP = 10; // ≤ 2000 events scanned per render (bounded)

export interface RecentAudit {
  /** Tail slice, oldest-first within the slice (caller may reverse for display). */
  events: AuditEventResponse[];
  /** Highest sequence_number observed — the cursor the client poller resumes from. */
  lastSequence: number;
  chainVerified: boolean;
  chainRowsChecked: number;
}

/**
 * Fetch up to `maxEvents` most-recent audit events for a tenant (bounded forward
 * paging). Effective max events returned is min(maxEvents, PAGE_LIMIT*PAGE_CAP).
 *
 * Chain status note: the admin audit-read recomputes the GLOBAL F-003 chain
 * validation on every call and returns the same `chain_verified` /
 * `chain_rows_checked` for the whole chain on each page (not a per-page slice).
 * Taking the last page's values is therefore correct — they describe the global
 * chain, identical across pages; they are NOT summed (summing would multiply the
 * global row count by the page count).
 */
export async function fetchRecentAudit(tenantId: string, maxEvents = 200): Promise<RecentAudit> {
  let after = 0;
  let pages = 0;
  let all: AuditEventResponse[] = [];
  let chainVerified = false;
  let chainRowsChecked = 0;

  // Page forward to the tail (bounded). Each page is the next ASC window.
  while (pages < PAGE_CAP) {
    const page = await adminApi.getAudit(tenantId, after, PAGE_LIMIT);
    chainVerified = page.chain_verified; // global chain status (same each page)
    chainRowsChecked = page.chain_rows_checked;
    if (page.events.length > 0) all = all.concat(page.events);
    pages += 1;
    if (page.next_cursor == null) break;
    // Defensive: the backend only sets next_cursor on a full page, so an empty
    // page should already null the cursor; bail anyway rather than chase it.
    if (page.events.length === 0) break;
    after = page.next_cursor;
  }

  const lastSequence = all.length > 0 ? all[all.length - 1].sequence_number : 0;
  const events = all.slice(-maxEvents); // most-recent tail
  return { events, lastSequence, chainVerified, chainRowsChecked };
}
