"use server";

import { revalidatePath } from "next/cache";

import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import type { ExternalSystemCreateRequest, ExternalSystemView, SyncRunCreateRequest, SyncRunView } from "@/lib/types";

/** Server Actions for the D-019 sync-connectors UI. Mirrors invoicing/actions.ts's
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

export async function createExternalSystemAction(
  input: ExternalSystemCreateRequest,
): Promise<ActionResult<ExternalSystemView>> {
  try {
    const system = await adminApi.createExternalSystem(input);
    revalidatePath("/integrations");
    return { ok: true, data: system };
  } catch (err) {
    return fromError(err, "Could not register the external system.");
  }
}

export async function runSyncAction(
  systemId: string,
  input: SyncRunCreateRequest,
): Promise<ActionResult<SyncRunView>> {
  try {
    const run = await adminApi.runSync(systemId, input);
    revalidatePath("/integrations");
    return { ok: true, data: run };
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 409) {
      return {
        ok: false,
        status: 409,
        message: err.detail ?? "This external system is disabled and cannot accept a sync.",
      };
    }
    return fromError(err, "Could not run the sync.");
  }
}
