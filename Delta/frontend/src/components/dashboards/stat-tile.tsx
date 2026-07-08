/** Stat-tile contract (dataviz skill): label (sentence case, no colon), value
 * (semibold, auto-compact), optional hint. No delta/trend here — D-008 has no
 * prior-period comparison built yet (see ADR-0008 honesty boundary). */
export function StatTile({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg-raised p-4">
      <div className="text-sm text-fg-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-fg">{value}</div>
      {hint ? <div className="mt-1 text-xs text-fg-faint">{hint}</div> : null}
    </div>
  );
}
