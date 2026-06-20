import { defineConfig, devices } from "@playwright/test";

// E2E / threat-vector lane. Boots the built console with canary secrets so the
// token-absence vectors (1, 2) and fail-closed vectors (3, 4, 5, 9) run end-to-end.
// Browsers are installed on demand (`npx playwright install`); CI runs the
// browser-free token grep (scripts/check-token-absence.mjs) instead.
const PORT = 3100;

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `npm run build && npm run start -- -p ${PORT}`,
    url: `http://127.0.0.1:${PORT}/login`,
    timeout: 180_000,
    reuseExistingServer: !process.env.CI,
    env: {
      SENTINEL_API_URL: "http://127.0.0.1:9", // unreachable on purpose; BFF tests mock or assert pre-upstream behavior
      SENTINEL_ADMIN_TOKEN: "pw-canary-admin-token-DO-NOT-SHIP",
      SESSION_SECRET: "pw-canary-session-secret-0123456789abcdef",
      NODE_ENV: "production",
    },
  },
});
