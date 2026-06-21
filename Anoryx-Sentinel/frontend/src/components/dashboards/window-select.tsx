"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { DEFAULT_WINDOW, TIME_WINDOWS } from "@/lib/dashboards";

/**
 * Shared timeframe selector (F-013). Writes `?window=1h|24h|7d` on the current
 * dashboard route, preserving the tenant scope. Server pages read the value for
 * their window-bounded queries (e.g. compliance evidence). Defaults to 24h.
 */
export function WindowSelect() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const current = params.get("window") ?? DEFAULT_WINDOW;

  function onChange(windowKey: string) {
    const next = new URLSearchParams(params.toString());
    next.set("window", windowKey);
    router.push(`${pathname}?${next.toString()}`);
  }

  return (
    <div className="flex items-center gap-2">
      <label htmlFor="dash-window" className="text-xs font-medium text-fg-muted">
        Window
      </label>
      <select
        id="dash-window"
        value={current}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-border bg-bg-inset px-3 py-1.5 text-sm text-fg"
      >
        {TIME_WINDOWS.map((w) => (
          <option key={w.key} value={w.key}>
            {w.label}
          </option>
        ))}
      </select>
    </div>
  );
}
