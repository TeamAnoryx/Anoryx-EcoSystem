import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

/**
 * Render lane: jsdom environment for DOM-assertion tests (React component
 * rendering). Kept separate from the node lane (vitest.config.ts) so the
 * existing server-side unit suite is unaffected. Only .test.tsx files are
 * included here.
 */
export default defineConfig({
  esbuild: {
    // Vitest uses esbuild for JSX transform — "automatic" runtime (React 17+)
    // avoids needing an explicit `import React` in every test file.
    jsx: "automatic",
    jsxImportSource: "react",
  },
  test: {
    environment: "jsdom",
    include: ["tests/unit/**/*.test.tsx"],
    globals: true,
    setupFiles: ["tests/unit/setup-dom.ts"],
  },
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
});
