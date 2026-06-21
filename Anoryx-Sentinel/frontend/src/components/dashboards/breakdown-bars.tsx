import type { CountBucket } from "@/lib/dashboards";

/**
 * Plain-CSS horizontal count bars (F-013 Fork 4 — zero charting deps). Bar width
 * is proportional to the max count. Labels render as inert text (R5). Used for
 * the Security per-team breakdown and per-type summary.
 */
export function BreakdownBars({
  buckets,
  label,
  emptyText = "No data in the loaded window.",
  mono = false,
}: {
  buckets: CountBucket[];
  label: string;
  emptyText?: string;
  mono?: boolean;
}) {
  const max = buckets.reduce((m, b) => Math.max(m, b.count), 0);

  return (
    <section className="space-y-2" aria-label={label}>
      <h3 className="text-sm font-medium text-fg-muted">{label}</h3>
      {buckets.length === 0 ? (
        <p className="text-sm text-fg-faint">{emptyText}</p>
      ) : (
        <ul className="space-y-1">
          {buckets.map((b) => {
            const pct = max > 0 ? Math.max(2, Math.round((b.count / max) * 100)) : 0;
            return (
              <li key={b.key} className="flex items-center gap-3">
                <span
                  className={`w-40 shrink-0 truncate text-xs text-fg ${mono ? "font-mono" : ""}`}
                  title={b.key}
                >
                  {b.key}
                </span>
                <span className="h-3 flex-1 overflow-hidden rounded-sm bg-bg-inset">
                  <span
                    className="block h-full rounded-sm bg-accent/70"
                    style={{ width: `${pct}%` }}
                    aria-hidden="true"
                  />
                </span>
                <span className="w-10 shrink-0 text-right font-mono text-xs text-fg-muted">
                  {b.count}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
