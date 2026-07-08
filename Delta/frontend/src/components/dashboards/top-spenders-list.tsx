import { formatMinorUnits } from "@/lib/money";
import type { GroupSpendView } from "@/lib/types";

/**
 * Ranked bar list (D-008). Magnitude encoding (bar length), not identity — one
 * hue, the entity's own label carries identity, so no legend/categorical palette
 * is needed (dataviz skill: color-by-identity vs. color-by-magnitude are
 * different jobs; this is the latter).
 */
export function TopSpendersList({ rows, currency }: { rows: GroupSpendView[]; currency: string }) {
  if (rows.length === 0) {
    return <p className="text-sm text-fg-faint">No spend recorded in this window.</p>;
  }
  const max = Math.max(...rows.map((r) => r.cost_cents), 1);

  return (
    <table className="w-full text-left text-sm">
      <caption className="sr-only">Top spenders ranked by cost, descending</caption>
      <tbody>
        {rows.map((r) => (
          <tr key={r.group_key}>
            <td className="w-1/3 truncate py-1.5 pr-3 font-mono text-xs text-fg-muted" title={r.group_key}>
              {r.group_key}
            </td>
            <td className="py-1.5">
              <div className="flex items-center gap-2">
                <div className="h-3 flex-1 overflow-hidden rounded-sm bg-bg-inset">
                  <div
                    className="h-full rounded-r-sm bg-accent"
                    style={{ width: `${Math.max((r.cost_cents / max) * 100, 2)}%` }}
                  />
                </div>
                <span className="w-24 shrink-0 text-right font-medium tabular-nums text-fg">
                  {formatMinorUnits(r.cost_cents, currency)}
                </span>
                <span className="w-16 shrink-0 text-right tabular-nums text-fg-muted">
                  {r.request_count} req
                </span>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
