import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Static defense-in-depth for R1 (mirrors the eslint rule):
 *  - `process.env` may be referenced ONLY in the env funnel + middleware.
 *  - `NEXT_PUBLIC_` must never appear (it would inline a value into the client).
 */

const SRC = join(process.cwd(), "src");
const ENV_ALLOWED = new Set([join("src", "lib", "env.ts"), join("src", "middleware.ts")]);

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (/\.(ts|tsx)$/.test(entry)) out.push(p);
  }
  return out;
}

describe("env / token leak guard (vector 1)", () => {
  const files = walk(SRC);

  it("never declares a NEXT_PUBLIC_ variable in src", () => {
    // Match a real var name (NEXT_PUBLIC_ followed by name chars), so prose that
    // merely mentions the prefix in a comment is not a false positive.
    const offenders = files.filter((f) => /\bNEXT_PUBLIC_[A-Z0-9_]+/.test(readFileSync(f, "utf8")));
    expect(offenders).toEqual([]);
  });

  it("references process.env only in the env funnel and middleware", () => {
    const offenders = files.filter((f) => {
      const rel = f.slice(process.cwd().length + 1);
      return readFileSync(f, "utf8").includes("process.env") && !ENV_ALLOWED.has(rel);
    });
    expect(offenders).toEqual([]);
  });
});
