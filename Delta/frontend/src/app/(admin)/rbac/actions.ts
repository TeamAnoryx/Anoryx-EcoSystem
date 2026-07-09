"use server";

import { revalidatePath } from "next/cache";

import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import type { AccessTokenCreateRequest, AccessTokenIssuedView, AccessTokenView } from "@/lib/types";

/** Server Actions for the D-017 access-token UI. Mirrors capacity/actions.ts's
 * discriminated-result shape exactly — `adminApi` is `server-only`, so
 * DELTA_ADMIN_TOKEN never reaches the browser either way. */
export type ActionResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; detail?: string; message: string };

function fromError(err: unknown, fallback: string): ActionResult<never> {
  if (err instanceof AdminApiError) {
    return { ok: false, status: err.status, detail: err.detail, message: err.detail ?? fallback };
  }
  return { ok: false, status: 500, message: fallback };
}

export async function createAccessTokenAction(
  input: AccessTokenCreateRequest,
): Promise<ActionResult<AccessTokenIssuedView>> {
  try {
    const token = await adminApi.createAccessToken(input);
    revalidatePath("/rbac");
    return { ok: true, data: token };
  } catch (err) {
    return fromError(err, "Could not issue the access token.");
  }
}

export async function revokeAccessTokenAction(
  tokenId: string,
  tenantId: string,
): Promise<ActionResult<AccessTokenView>> {
  try {
    const token = await adminApi.revokeAccessToken(tokenId, { tenant_id: tenantId });
    revalidatePath("/rbac");
    return { ok: true, data: token };
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 404) {
      return { ok: false, status: 404, message: "That token no longer exists." };
    }
    return fromError(err, "Could not revoke the token.");
  }
}
