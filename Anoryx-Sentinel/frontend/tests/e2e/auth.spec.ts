import { expect, test } from "@playwright/test";

/**
 * Browser threat vectors (ADR-0015 §11). The webServer (playwright.config.ts)
 * boots the built console with canary secrets and an unreachable SENTINEL_API_URL.
 */

test("vector 3 — no session redirects to login, renders no admin data", async ({ page }) => {
  const res = await page.goto("/");
  expect(page.url()).toContain("/login");
  // The protected shell ("Operator console") must not appear pre-auth.
  await expect(page.getByText("Operator console")).toHaveCount(0);
  expect(res?.status()).toBeLessThan(500);
});

test("vector 8 — strict CSP header present, no script unsafe-inline", async ({ page }) => {
  const res = await page.goto("/login");
  const csp = res?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("default-src 'self'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("object-src 'none'");
  // script-src must not weaken to 'unsafe-inline'.
  const scriptSrc = csp.split(";").find((d) => d.trim().startsWith("script-src")) ?? "";
  expect(scriptSrc).not.toContain("'unsafe-inline'");
});

test("vector 1/2 — login page source carries no admin token", async ({ page }) => {
  await page.goto("/login");
  const html = await page.content();
  expect(html).not.toContain("pw-canary-admin-token-DO-NOT-SHIP");
});

test("security headers present on login", async ({ page }) => {
  const res = await page.goto("/login");
  const h = res?.headers() ?? {};
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["referrer-policy"]).toBe("no-referrer");
});
