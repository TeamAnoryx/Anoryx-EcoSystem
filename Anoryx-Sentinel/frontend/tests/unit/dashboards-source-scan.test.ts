import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

/**
 * Static structural guards for the F-013 dashboards (run in the node CI lane,
 * unlike the browser e2e vectors):
 *  - Vector 5 (XSS): no dashboard file uses dangerouslySetInnerHTML — every API
 *    field renders as inert React text.
 *  - Vector 2 (BFF-only): client ("use client") dashboard components never import
 *    the server-only admin client or env funnel, so they cannot call Sentinel
 *    directly or touch the admin token.
 */

const ROOTS = ["src/components/dashboards", "src/app/(admin)/dashboards"];

function walk(dir: string): string[] {
  let out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out = out.concat(walk(full));
    else if (full.endsWith(".tsx") || full.endsWith(".ts")) out.push(full);
  }
  return out;
}

const files = ROOTS.flatMap((r) => walk(join(process.cwd(), r)));

describe("dashboards source guards", () => {
  it("scans a non-trivial set of dashboard files", () => {
    expect(files.length).toBeGreaterThan(8);
  });

  it("vector 5 — no dangerouslySetInnerHTML usage anywhere in the dashboards", () => {
    // Match the JSX attribute form (prose mentions in comments are not usage).
    const usage = /dangerouslySetInnerHTML\s*=/;
    const offenders = files.filter((f) => usage.test(readFileSync(f, "utf8")));
    expect(offenders).toEqual([]);
  });

  it("vector 2 — client dashboard components never import server-only admin/env modules", () => {
    const offenders: string[] = [];
    for (const f of files) {
      const src = readFileSync(f, "utf8");
      const isClient = src.includes('"use client"') || src.includes("'use client'");
      if (!isClient) continue;
      if (
        src.includes("@/lib/admin-client") ||
        src.includes("@/lib/dashboards-server") ||
        src.includes("@/lib/env")
      ) {
        offenders.push(f);
      }
    }
    expect(offenders).toEqual([]);
  });
});
