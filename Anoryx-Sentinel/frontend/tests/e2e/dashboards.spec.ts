import { expect, test } from "@playwright/test";

/**
 * Dashboard browser vectors (F-013, ADR-0016 §6). The webServer boots the built
 * console with canary secrets + an unreachable SENTINEL_API_URL, so these run
 * pre-auth: every dashboard route must fail closed to /login (vector 1) and keep
 * the strict CSP (vector 8). Data-path vectors (2/3/5/7) are covered by the node
 * unit lane (clientApi BFF prefix, source scan, poll gate, aggregation).
 */

const ROUTES = ["/dashboards/security", "/dashboards/compliance", "/dashboards/governance"];

for (const route of ROUTES) {
  test(`vector 1 — ${route} requires a session (redirects to login)`, async ({ page }) => {
    const res = await page.goto(route);
    expect(page.url()).toContain("/login");
    expect(res?.status()).toBeLessThan(500);
  });
}

test("vector 1 — dashboard route source carries no admin token", async ({ page }) => {
  await page.goto("/dashboards/security");
  const html = await page.content();
  expect(html).not.toContain("pw-canary-admin-token-DO-NOT-SHIP");
});

test("vector 8 — strict CSP (no script unsafe-inline) on a dashboard route", async ({ page }) => {
  const res = await page.goto("/dashboards/security");
  const csp = res?.headers()["content-security-policy"] ?? "";
  const scriptSrc = csp.split(";").find((d) => d.trim().startsWith("script-src")) ?? "";
  expect(scriptSrc).not.toContain("'unsafe-inline'");
  expect(csp).toContain("frame-ancestors 'none'");
});
