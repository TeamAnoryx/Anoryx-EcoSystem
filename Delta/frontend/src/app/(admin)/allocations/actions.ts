"use server";

import { revalidatePath } from "next/cache";

import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import type { AllocationCreateRequest, AllocationView, ApprovalDecisionRequest } from "@/lib/types";

/**
 * Server Actions for the allocations UI (D-007). Chosen over plain
 * `<form action={fn}>` + `useFormState` so the client components below can
 * `try/catch` around a direct call and render inline errors without the
 * extra `useFormState` wiring — these are still ordinary Server Actions
 * ("use server"), so they run only on the server; the browser never sees
 * DELTA_ADMIN_TOKEN either way (adminApi is `server-only`).
 *
 * Actions return a discriminated result instead of throwing across the
 * server/client boundary, so callers get a typed, predictable shape (status +
 * the upstream `detail`) rather than relying on how Next.js happens to
 * serialize a thrown Error's message in the current version.
 */
export type ActionResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; detail?: string; message: string };

export async function createAllocationAction(
  input: AllocationCreateRequest,
): Promise<ActionResult<AllocationView>> {
  try {
    const allocation = await adminApi.createAllocation(input);
    revalidatePath("/allocations");
    return { ok: true, data: allocation };
  } catch (err) {
    if (err instanceof AdminApiError) {
      return {
        ok: false,
        status: err.status,
        detail: err.detail,
        // 422 = the targets don't reconcile to total_minor_units; the upstream
        // `detail` string is the human-readable reconciliation error and is
        // safe to show verbatim (it never contains upstream internals).
        message: err.detail ?? "Could not create the allocation.",
      };
    }
    return { ok: false, status: 500, message: "Unexpected error creating the allocation." };
  }
}

export async function decideAllocationAction(
  allocationId: string,
  input: ApprovalDecisionRequest,
): Promise<ActionResult<AllocationView>> {
  try {
    const allocation = await adminApi.decideAllocation(allocationId, input);
    revalidatePath(`/allocations/${allocationId}`);
    revalidatePath("/allocations");
    return { ok: true, data: allocation };
  } catch (err) {
    if (err instanceof AdminApiError) {
      let message: string;
      if (err.status === 409) {
        // Expected, real outcome (someone else decided first) — not a generic
        // error toast.
        message = "This allocation was already decided by someone else. Refresh to see the outcome.";
      } else if (err.status === 404) {
        message = "This allocation no longer exists for this tenant.";
      } else {
        message = err.detail ?? "Could not record the decision.";
      }
      return { ok: false, status: err.status, detail: err.detail, message };
    }
    return { ok: false, status: 500, message: "Unexpected error recording the decision." };
  }
}
