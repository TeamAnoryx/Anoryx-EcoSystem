import { NextResponse, type NextRequest } from "next/server";

import { handleAdminProxy } from "@/lib/bff";
import { isCrossSite } from "@/lib/request-guard";
import { getSession } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * BFF catch-all for client-initiated admin calls (ADR-0015 D2, ADR-0017 D8).
 * Thin adapter: resolve the session, hand the request parts to the tested proxy
 * core, and serialize the result.
 *
 * The admin token (break-glass) and the operator-session bearer (SSO) are never
 * touched here — they are resolved inside handleAdminProxy based on `session.kind`,
 * server-side only (R6 / vectors 2, 5).
 */
async function handle(
  request: NextRequest,
  context: { params: { path?: string[] } },
  method: "GET" | "POST" | "PATCH",
): Promise<NextResponse> {
  // CSRF defense-in-depth on state-changing methods (security-audit L1).
  if (method !== "GET" && isCrossSite(request)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  let body: string | undefined;
  if (method === "POST" || method === "PATCH") {
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
export const PATCH = (req: NextRequest, ctx: { params: { path?: string[] } }) =>
  handle(req, ctx, "PATCH");
