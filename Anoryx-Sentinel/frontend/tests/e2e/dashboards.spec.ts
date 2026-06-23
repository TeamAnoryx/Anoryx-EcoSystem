import { expect, test } from "@playwright/test";

/**
 * Dashboard browser vectors (F-013, ADR-0016 §6; F-018, ADR-0021 §9).
 *
 * The webServer boots the built console with canary secrets + an unreachable
 * SENTINEL_API_URL, so these run pre-auth: every dashboard route must fail
 * closed to /login (vector 1) and keep the strict CSP (vector 8).
 *
 * F-018 (shadow-AI panel, vectors 1/3): the governance route is unauthenticated
 * in this harness (redirects to login), so the panel rendering is covered by
 * the node unit lane. The structural guarantees below are the e2e layer:
 *  - The governance route participates in the same auth redirect (vector 1).
 *  - The page source must not contain the admin token (shared vector 1 canary).
 *  - The CSP check applies to the governance route too.
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

// ---- F-018 shadow-AI panel structural checks (ADR-0021 §9, vectors 1, 3) -- //

test(
  "F-018 vector 1 — governance route participates in auth redirect (disclaimer rendered only post-auth)",
  async ({ page }) => {
    const res = await page.goto("/dashboards/governance");
    // Pre-auth the governance page must redirect to login, the same as all
    // other dashboard routes — the shadow-AI panel is never exposed to
    // unauthenticated visitors.
    expect(page.url()).toContain("/login");
    expect(res?.status()).toBeLessThan(500);
  },
);

test("F-018 vector 1 — governance page source carries no admin token", async ({ page }) => {
  await page.goto("/dashboards/governance");
  const html = await page.content();
  expect(html).not.toContain("pw-canary-admin-token-DO-NOT-SHIP");
});

test(
  "F-018 vector 8 — strict CSP on the governance route (shadow-AI panel must not weaken it)",
  async ({ page }) => {
    const res = await page.goto("/dashboards/governance");
    const csp = res?.headers()["content-security-policy"] ?? "";
    const scriptSrc = csp.split(";").find((d) => d.trim().startsWith("script-src")) ?? "";
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(csp).toContain("frame-ancestors 'none'");
  },
);
