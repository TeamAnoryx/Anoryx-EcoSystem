"use server";

import { revalidatePath } from "next/cache";

import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import type {
  InvoiceCreateRequest,
  InvoiceDecisionRequest,
  InvoicePaymentView,
  InvoiceView,
  PaymentRecordRequest,
} from "@/lib/types";

/** Server Actions for the D-018 invoicing UI. Mirrors erp/actions.ts's discriminated-
 * result shape exactly — `adminApi` is `server-only`, so DELTA_ADMIN_TOKEN never
 * reaches the browser either way. */
export type ActionResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; detail?: string; message: string };

function fromError(err: unknown, fallback: string): ActionResult<never> {
  if (err instanceof AdminApiError) {
    return { ok: false, status: err.status, detail: err.detail, message: err.detail ?? fallback };
  }
  return { ok: false, status: 500, message: fallback };
}

export async function createInvoiceAction(
  input: InvoiceCreateRequest,
): Promise<ActionResult<InvoiceView>> {
  try {
    const invoice = await adminApi.createInvoice(input);
    revalidatePath("/invoicing");
    return { ok: true, data: invoice };
  } catch (err) {
    return fromError(err, "Could not submit the invoice.");
  }
}

export async function decideInvoiceAction(
  invoiceId: string,
  input: InvoiceDecisionRequest,
): Promise<ActionResult<InvoiceView>> {
  try {
    const invoice = await adminApi.decideInvoice(invoiceId, input);
    revalidatePath("/invoicing");
    return { ok: true, data: invoice };
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 409) {
      return {
        ok: false,
        status: 409,
        message: "This invoice was already decided by someone else. Refresh to see the outcome.",
      };
    }
    return fromError(err, "Could not record the decision.");
  }
}

export async function recordInvoicePaymentAction(
  invoiceId: string,
  input: PaymentRecordRequest,
): Promise<ActionResult<InvoicePaymentView>> {
  try {
    const payment = await adminApi.recordInvoicePayment(invoiceId, input);
    revalidatePath("/invoicing");
    return { ok: true, data: payment };
  } catch (err) {
    if (err instanceof AdminApiError && (err.status === 409 || err.status === 422)) {
      return {
        ok: false,
        status: err.status,
        message:
          err.detail ??
          "This payment could not be recorded — the invoice may not be payable, or this would exceed its remaining balance.",
      };
    }
    return fromError(err, "Could not record the payment.");
  }
}
