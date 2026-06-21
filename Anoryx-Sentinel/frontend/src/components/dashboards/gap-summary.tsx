import { Badge } from "@/components/ui/badge";
import { AUDIT_READY_LABEL, type ReadinessView } from "@/lib/dashboards";

/**
 * Compliance readiness + status totals (F-013 compliance panel). Honest
 * rendering (R6 / F-011 R8): shows the "audit-ready, not compliant" framing and
 * the mandatory disclaimer; gaps and not-covered are shown as their own counts,
 * never folded into a coverage claim. The per-control list is NOT rendered —
 * the operator endpoint returns aggregate totals only (ADR-0016 deferral 2b).
 * All values render as inert text (R5).
 */
export function GapSummary({ view }: { view: ReadinessView }) {
  const cells: Array<{ label: string; value: number; tone: "ok" | "warn" | "danger" | "neutral" }> = [
    { label: "Passed", value: view.passed, tone: "ok" },
    { label: "Gap", value: view.gap, tone: "warn" },
    { label: "Not covered", value: view.notCovered, tone: "danger" },
    { label: "Not applicable", value: view.notApplicable, tone: "neutral" },
  ];

  return (
    <section className="space-y-4" aria-label="Compliance readiness">
      <div className="flex flex-wrap items-baseline gap-3">
        <span className="text-3xl font-semibold text-fg">{view.percent}</span>
        <span className="text-sm text-fg-muted">
          readiness · {view.framework} {view.frameworkVersion}
        </span>
        <Badge tone="warn">{AUDIT_READY_LABEL}</Badge>
      </div>

      <p className="text-xs text-fg-muted">
        Readiness = passed / applicable ({view.passed}/{view.applicable}). {view.total} controls
        total.
      </p>

      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {cells.map((c) => (
          <div key={c.label} className="rounded-lg border border-border bg-bg-raised p-3">
            <dt className="text-xs text-fg-muted">{c.label}</dt>
            <dd className="mt-1 flex items-center gap-2">
              <span className="font-mono text-lg text-fg">{c.value}</span>
              <Badge tone={c.tone}>{c.label.toLowerCase()}</Badge>
            </dd>
          </div>
        ))}
      </dl>

      <p className="text-xs text-fg-faint">{view.disclaimer}</p>
    </section>
  );
}
