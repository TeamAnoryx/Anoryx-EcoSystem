import { Badge } from "@/components/ui/badge";

/**
 * Placeholder for an F-013 dashboard. The route, nav entry, layout, and auth
 * guard all exist now; F-013 fills the body without touching them (ADR-0015 D6).
 */
export function DashboardStub({
  title,
  summary,
  planned,
}: {
  title: string;
  summary: string;
  planned: string[];
}) {
  return (
    <section className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold text-fg">{title}</h1>
        <Badge tone="warn">Coming in F-013</Badge>
      </div>
      <p className="max-w-2xl text-sm text-fg-muted">{summary}</p>
      <div className="rounded-lg border border-dashed border-border-strong bg-bg-raised p-6">
        <h2 className="text-sm font-medium text-fg-muted">Planned contents</h2>
        <ul className="mt-2 list-inside list-disc space-y-1 text-sm text-fg-muted">
          {planned.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}
