import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE } from "@/lib/cookie-name";

/**
 * Route guard (D-007). Redirects unauthenticated requests to /login.
 *
 * Scope note: Next.js middleware runs on the Edge runtime, which has no
 * `node:crypto`, so this layer can only check for the PRESENCE of the signed
 * session cookie (a cheap, edge-safe UX redirect for the common "never logged
 * in" / "logged out" case). It is NOT the security boundary: a forged or
 * tampered cookie would pass this check. The actual fail-closed enforcement —
 * full HMAC verification via `getSession()` (src/lib/session.ts, Node runtime)
 * — happens in `src/app/(admin)/layout.tsx`, which every admin page sits under,
 * and independently again in the BFF proxy core (`src/lib/bff.ts`). This
 * mirrors Anoryx-Sentinel/frontend's layered approach (middleware sets
 * security headers there; the admin route group layout is the authoritative
 * session gate).
 */
const PUBLIC_PATHS = ["/login", "/api/login"];

function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (isPublicPath(pathname)) {
    return NextResponse.next();
  }

  const hasSessionCookie = Boolean(request.cookies.get(SESSION_COOKIE)?.value);
  if (!hasSessionCookie) {
    const loginUrl = new URL("/login", request.url);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  // Apply to every route except Next's static assets, favicon, and the logout
  // route (which must be reachable to clear a stale/expired cookie).
  matcher: [
    {
      source: "/((?!_next/static|_next/image|favicon.ico|api/logout).*)",
    },
  ],
};
