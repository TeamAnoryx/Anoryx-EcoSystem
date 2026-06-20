import { NextResponse, type NextRequest } from "next/server";

/**
 * Security headers + strict CSP with a per-request nonce (ADR-0015 D7, vector 8).
 *
 * script-src uses a nonce + 'strict-dynamic' and NO 'unsafe-inline' — the
 * load-bearing XSS control. style-src allows 'unsafe-inline' (Tailwind/Next inject
 * inline styles; style injection is far lower risk than script). In dev,
 * 'unsafe-eval' is added for React Fast Refresh only.
 */
export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  // Fail-closed: only an explicit development env relaxes the script policy with
  // 'unsafe-eval' (for Fast Refresh). Any unknown/test/preview env stays strict
  // (security-audit L2).
  const isDev = process.env.NODE_ENV === "development";
  const scriptSrc = `'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`;

  const csp = [
    `default-src 'self'`,
    `script-src ${scriptSrc}`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data:`,
    `font-src 'self'`,
    `connect-src 'self'`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`,
    `upgrade-insecure-requests`,
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  // Next reads this from the request headers to nonce its own bootstrap scripts.
  requestHeaders.set("content-security-policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "no-referrer");
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  // No `preload` from the app layer (security-audit L3) — preload/includeSubDomains
  // policy belongs at the TLS edge (Caddy) where the domain topology is known.
  response.headers.set("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  return response;
}

export const config = {
  // Apply to every route except Next's static assets + favicon.
  matcher: [
    {
      source: "/((?!_next/static|_next/image|favicon.ico).*)",
      missing: [{ type: "header", key: "next-router-prefetch" }],
    },
  ],
};
