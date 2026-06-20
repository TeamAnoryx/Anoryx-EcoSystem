#!/usr/bin/env node
/**
 * Vector 1 (load-bearing): the built client output must contain NO admin token.
 *
 * Usage (CI + local): build with a canary token, then run this script with the
 * same value in SENTINEL_ADMIN_TOKEN. It walks the client-shipped build output
 * (.next/static + the standalone client chunks) and fails if the value appears.
 *
 *   SENTINEL_ADMIN_TOKEN=__canary__ SESSION_SECRET=__x__ npm run build
 *   SENTINEL_ADMIN_TOKEN=__canary__ npm run check:token
 */
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join } from "node:path";

const token = process.env.SENTINEL_ADMIN_TOKEN;
if (!token || token.length < 8) {
  console.error("check:token — set SENTINEL_ADMIN_TOKEN to the canary used at build time.");
  process.exit(2);
}

// Directories that ship to the browser.
const roots = [join(".next", "static")].filter(existsSync);
if (roots.length === 0) {
  console.error("check:token — no build output found. Run `npm run build` first.");
  process.exit(2);
}

let scanned = 0;
const hits = [];
function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p);
    else {
      scanned += 1;
      try {
        if (readFileSync(p, "utf8").includes(token)) hits.push(p);
      } catch {
        /* binary / unreadable — skip */
      }
    }
  }
}
for (const r of roots) walk(r);

if (hits.length > 0) {
  console.error(`check:token — FAIL: admin token found in ${hits.length} client file(s):`);
  for (const h of hits) console.error(`  ${h}`);
  process.exit(1);
}
console.log(`check:token — OK: scanned ${scanned} client file(s); admin token absent.`);
