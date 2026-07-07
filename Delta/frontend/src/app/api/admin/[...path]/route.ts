import { NextResponse, type NextRequest } from "next/server";

import { handleAdminProxy } from "@/lib/bff";
import { isCrossSite } from "@/lib/request-guard";
import { getSession } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * BFF catch-all for client-initiated admin calls (D-007, mirrors
 * Anoryx-Sentinel/frontend's src/app/api/admin/[...path]/route.ts). Thin
 * adapter: resolve the session, hand the request parts to the tested proxy
 * core, and serialize the result.
 *
 * The app's own pages (allocations, history) call `adminApi` directly from
 * server components / Server Actions (see src/lib/admin-client.ts) and do NOT
 * go through this route today — but it is still built + tested per this
 * monorepo's BFF-only-frontend convention, as the documented seam for any
 * future client-fetch or non-page consumer. See README.md for the exact
 * per-path mechanism.
 */
async function handle(
  request: NextRequest,
  context: { params: { path?: string[] } },
  method: "GET" | "POST",
): Promise<NextResponse> {
  // CSRF defense-in-depth on state-changing methods.
  if (method !== "GET" && isCrossSite(request)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  let body: string | undefined;
  if (method === "POST") {
    const text = await request.text();
    body = text.length > 0 ? text : undefined;
  }

  const result = await handleAdminProxy({
    session: getSession(),
    segments: context.params.path ?? [],
    search: request.nextUrl.searchParams,
    method,
    body,
  });

  if (result.status === 204) return new NextResponse(null, { status: 204 });
  return NextResponse.json(result.body, { status: result.status });
}

export const GET = (req: NextRequest, ctx: { params: { path?: string[] } }) =>
  handle(req, ctx, "GET");
export const POST = (req: NextRequest, ctx: { params: { path?: string[] } }) =>
  handle(req, ctx, "POST");
