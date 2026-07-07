import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { adminToken, cookieSecure, deltaApiUrl, sessionSecret } from "@/lib/env";

/**
 * Fail-loud env guard (mirrors Anoryx-Sentinel/frontend's env-guard.test.ts,
 * extended with functional assertions on the funnel functions themselves).
 */

const REQUIRED = ["DELTA_API_URL", "DELTA_ADMIN_TOKEN", "SESSION_SECRET", "NODE_ENV"] as const;
let saved: Partial<Record<(typeof REQUIRED)[number], string | undefined>>;

/** NODE_ENV is typed readonly on process.env; this is the sanctioned test-only escape hatch. */
function setEnv(key: (typeof REQUIRED)[number], value: string): void {
  (process.env as Record<string, string>)[key] = value;
}

beforeEach(() => {
  saved = {};
  for (const k of REQUIRED) saved[k] = process.env[k];
});

afterEach(() => {
  for (const k of REQUIRED) {
    if (saved[k] === undefined) delete (process.env as Record<string, string | undefined>)[k];
    else setEnv(k, saved[k] as string);
  }
});

describe("env — fail-loud on missing required vars", () => {
  it("deltaApiUrl throws when DELTA_API_URL is missing", () => {
    delete process.env.DELTA_API_URL;
    expect(() => deltaApiUrl()).toThrow(/DELTA_API_URL/);
  });

  it("deltaApiUrl throws when DELTA_API_URL is whitespace-only", () => {
    setEnv("DELTA_API_URL", "   ");
    expect(() => deltaApiUrl()).toThrow(/DELTA_API_URL/);
  });

  it("deltaApiUrl throws a clear error on a malformed URL", () => {
    setEnv("DELTA_API_URL", "not-a-url");
    expect(() => deltaApiUrl()).toThrow(/not a valid URL/);
  });

  it("deltaApiUrl returns the origin only, stripping any path", () => {
    setEnv("DELTA_API_URL", "http://localhost:8010/some/stray/path");
    expect(deltaApiUrl()).toBe("http://localhost:8010");
  });

  it("adminToken throws when DELTA_ADMIN_TOKEN is missing", () => {
    delete process.env.DELTA_ADMIN_TOKEN;
    expect(() => adminToken()).toThrow(/DELTA_ADMIN_TOKEN/);
  });

  it("adminToken returns the configured value", () => {
    setEnv("DELTA_ADMIN_TOKEN", "canary-token");
    expect(adminToken()).toBe("canary-token");
  });

  it("sessionSecret throws when SESSION_SECRET is missing", () => {
    delete process.env.SESSION_SECRET;
    expect(() => sessionSecret()).toThrow(/SESSION_SECRET/);
  });

  it("cookieSecure is false only in development, true otherwise", () => {
    setEnv("NODE_ENV", "development");
    expect(cookieSecure()).toBe(false);
    setEnv("NODE_ENV", "production");
    expect(cookieSecure()).toBe(true);
    setEnv("NODE_ENV", "test");
    expect(cookieSecure()).toBe(true);
  });
});

// ─── Static defense-in-depth (mirrors the eslint no-restricted-properties rule) ─

const SRC = join(process.cwd(), "src");
const ENV_ALLOWED = new Set([join("src", "lib", "env.ts")]);

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (/\.(ts|tsx)$/.test(entry)) out.push(p);
  }
  return out;
}

describe("env / token leak guard (static scan)", () => {
  const files = walk(SRC);

  it("never declares a NEXT_PUBLIC_ variable in src", () => {
    const offenders = files.filter((f) => /\bNEXT_PUBLIC_[A-Z0-9_]+/.test(readFileSync(f, "utf8")));
    expect(offenders).toEqual([]);
  });

  it("references process.env only in the env funnel", () => {
    const offenders = files.filter((f) => {
      const rel = f.slice(process.cwd().length + 1);
      return readFileSync(f, "utf8").includes("process.env") && !ENV_ALLOWED.has(rel);
    });
    expect(offenders).toEqual([]);
  });
});
