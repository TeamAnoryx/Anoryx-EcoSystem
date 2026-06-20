import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// Unit lane: pure server-side lib logic (session, env guard, error mapping). Node
// environment — no DOM. Browser/UX threat vectors run under Playwright (tests/e2e).
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/unit/**/*.test.ts"],
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
});
