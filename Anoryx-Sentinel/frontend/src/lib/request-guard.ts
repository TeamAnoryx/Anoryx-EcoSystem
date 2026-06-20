import type { NextRequest } from "next/server";

/**
 * CSRF defense-in-depth (security-audit L1). SameSite=Strict is the primary
 * control; this adds an explicit cross-site rejection on state-changing routes.
 *
 * Modern browsers always send Sec-Fetch-Site. 'same-origin' = the console's own
 * fetches; 'none' = a direct navigation or non-browser client. Anything else
 * ('cross-site' / 'same-site') is rejected.
 */
export function isCrossSite(request: NextRequest): boolean {
  const sfs = request.headers.get("sec-fetch-site");
  return sfs !== null && sfs !== "same-origin" && sfs !== "none";
}
