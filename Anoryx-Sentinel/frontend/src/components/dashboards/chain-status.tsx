import { Badge } from "@/components/ui/badge";

/**
 * F-003 hash-chain / signature verification badge (F-013 security panel). Reuses
 * the exact pattern from the audit viewer (tenants/[id]/audit) so the chain
 * status is reported honestly (vector 11 carried from F-012a): verified vs
 * INVALID, with the rows-checked count.
 */
export function ChainStatus({ verified, rowsChecked }: { verified: boolean; rowsChecked: number }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-sm text-fg-muted">Audit chain</span>
      <Badge tone={verified ? "ok" : "danger"}>
        {verified ? "chain verified" : "chain INVALID"} · {rowsChecked} rows
      </Badge>
    </div>
  );
}
