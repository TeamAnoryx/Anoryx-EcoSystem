"use server";

import { revalidatePath } from "next/cache";

import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import type {
  AssetCreateRequest,
  AssetStatusTransitionRequest,
  AssetView,
  PurchaseOrderCreateRequest,
  PurchaseOrderDecisionRequest,
  PurchaseOrderView,
  VendorCreateRequest,
  VendorView,
} from "@/lib/types";

/** Server Actions for the D-014 ERP UI. Mirrors crm/actions.ts's discriminated-result
 * shape exactly — `adminApi` is `server-only`, so DELTA_ADMIN_TOKEN never reaches the
 * browser either way. */
export type ActionResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; detail?: string; message: string };

function fromError(err: unknown, fallback: string): ActionResult<never> {
  if (err instanceof AdminApiError) {
    return { ok: false, status: err.status, detail: err.detail, message: err.detail ?? fallback };
  }
  return { ok: false, status: 500, message: fallback };
}

export async function createVendorAction(
  input: VendorCreateRequest,
): Promise<ActionResult<VendorView>> {
  try {
    const vendor = await adminApi.createVendor(input);
    revalidatePath("/erp");
    return { ok: true, data: vendor };
  } catch (err) {
    return fromError(err, "Could not create the vendor.");
  }
}

export async function createAssetAction(
  input: AssetCreateRequest,
): Promise<ActionResult<AssetView>> {
  try {
    const asset = await adminApi.createAsset(input);
    revalidatePath("/erp");
    return { ok: true, data: asset };
  } catch (err) {
    return fromError(err, "Could not create the asset.");
  }
}

export async function transitionAssetStatusAction(
  assetId: string,
  input: AssetStatusTransitionRequest,
): Promise<ActionResult<AssetView>> {
  try {
    const asset = await adminApi.transitionAssetStatus(assetId, input);
    revalidatePath("/erp");
    return { ok: true, data: asset };
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 409) {
      return {
        ok: false,
        status: 409,
        message: err.detail ?? "This asset cannot move to that status from its current one.",
      };
    }
    return fromError(err, "Could not update the asset status.");
  }
}

export async function createPurchaseOrderAction(
  input: PurchaseOrderCreateRequest,
): Promise<ActionResult<PurchaseOrderView>> {
  try {
    const po = await adminApi.createPurchaseOrder(input);
    revalidatePath("/erp");
    return { ok: true, data: po };
  } catch (err) {
    return fromError(err, "Could not create the purchase order.");
  }
}

export async function decidePurchaseOrderAction(
  poId: string,
  input: PurchaseOrderDecisionRequest,
): Promise<ActionResult<PurchaseOrderView>> {
  try {
    const po = await adminApi.decidePurchaseOrder(poId, input);
    revalidatePath("/erp");
    return { ok: true, data: po };
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 409) {
      return {
        ok: false,
        status: 409,
        message: "This purchase order was already decided by someone else. Refresh to see the outcome.",
      };
    }
    return fromError(err, "Could not record the decision.");
  }
}
