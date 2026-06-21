"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

/** Compliance framework selector (SOC2 / ISO27001). Writes `?framework=`. */
const FRAMEWORKS = ["SOC2", "ISO27001"] as const;
export const DEFAULT_FRAMEWORK = "SOC2";

export function FrameworkSelect() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const current = params.get("framework") ?? DEFAULT_FRAMEWORK;

  function onChange(framework: string) {
    const next = new URLSearchParams(params.toString());
    next.set("framework", framework);
    router.push(`${pathname}?${next.toString()}`);
  }

  return (
    <div className="flex items-center gap-2">
      <label htmlFor="dash-framework" className="text-xs font-medium text-fg-muted">
        Framework
      </label>
      <select
        id="dash-framework"
        value={current}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-border bg-bg-inset px-3 py-1.5 text-sm text-fg"
      >
        {FRAMEWORKS.map((f) => (
          <option key={f} value={f}>
            {f}
          </option>
        ))}
      </select>
    </div>
  );
}
