import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

// Unit lane: pure server-side lib logic (session, env guard, error mapping,
// admin-client). Node environment — no DOM.
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/unit/**/*.test.ts"],
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      // `server-only` throws unconditionally under its default export
      // condition; Next's bundler resolves it to `empty.js` via the
      // `react-server` package.json export condition when compiling server
      // code. Vitest (plain Node, no Next loader) doesn't apply that
      // condition, so alias directly to the same no-op file Next uses — this
      // lets tests import src/lib/env.ts and src/lib/admin-client.ts (both
      // legitimately server-only) without a Next runtime.
      "server-only": fileURLToPath(new URL("./node_modules/server-only/empty.js", import.meta.url)),
    },
  },
});
