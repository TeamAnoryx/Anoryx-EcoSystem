"use server";

import { revalidatePath } from "next/cache";

import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import type {
  ClientCreateRequest,
  ClientView,
  DealCreateRequest,
  DealStageTransitionRequest,
  DealView,
  InteractionCreateRequest,
  InteractionView,
  StakeholderCreateRequest,
  StakeholderView,
} from "@/lib/types";

/**
 * Server Actions for the D-013 CRM UI. Mirrors allocations/actions.ts's
 * discriminated-result shape exactly — `adminApi` is `server-only`, so
 * DELTA_ADMIN_TOKEN never reaches the browser either way.
 */
export type ActionResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; detail?: string; message: string };

function fromError(err: unknown, fallback: string): ActionResult<never> {
  if (err instanceof AdminApiError) {
    return { ok: false, status: err.status, detail: err.detail, message: err.detail ?? fallback };
  }
  return { ok: false, status: 500, message: fallback };
}

export async function createClientAction(
  input: ClientCreateRequest,
): Promise<ActionResult<ClientView>> {
  try {
    const client = await adminApi.createClient(input);
    revalidatePath("/crm");
    return { ok: true, data: client };
  } catch (err) {
    return fromError(err, "Could not create the client.");
  }
}

export async function createDealAction(
  clientId: string,
  input: DealCreateRequest,
): Promise<ActionResult<DealView>> {
  try {
    const deal = await adminApi.createDeal(clientId, input);
    revalidatePath(`/crm/${clientId}`);
    return { ok: true, data: deal };
  } catch (err) {
    return fromError(err, "Could not create the deal.");
  }
}

export async function transitionDealStageAction(
  clientId: string,
  dealId: string,
  input: DealStageTransitionRequest,
): Promise<ActionResult<DealView>> {
  try {
    const deal = await adminApi.transitionDealStage(dealId, input);
    revalidatePath(`/crm/${clientId}`);
    return { ok: true, data: deal };
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 409) {
      return {
        ok: false,
        status: 409,
        message: "This deal is already won/lost — its stage can no longer change.",
      };
    }
    return fromError(err, "Could not update the deal stage.");
  }
}

export async function createStakeholderAction(
  clientId: string,
  input: StakeholderCreateRequest,
): Promise<ActionResult<StakeholderView>> {
  try {
    const stakeholder = await adminApi.createStakeholder(clientId, input);
    revalidatePath(`/crm/${clientId}`);
    return { ok: true, data: stakeholder };
  } catch (err) {
    return fromError(err, "Could not add the stakeholder.");
  }
}

export async function createInteractionAction(
  clientId: string,
  input: InteractionCreateRequest,
): Promise<ActionResult<InteractionView>> {
  try {
    const interaction = await adminApi.createInteraction(clientId, input);
    revalidatePath(`/crm/${clientId}`);
    return { ok: true, data: interaction };
  } catch (err) {
    return fromError(err, "Could not log the interaction.");
  }
}
