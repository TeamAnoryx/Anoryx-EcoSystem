"use server";

import { revalidatePath } from "next/cache";

import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import type {
  AccountCreateRequest,
  AccountView,
  BudgetCreateRequest,
  BudgetView,
  TransactionCreateRequest,
  TransactionView,
} from "@/lib/types";

/** Server Actions for the D-021 personal-finance UI. Mirrors invoicing/actions.ts's
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

export async function createAccountAction(
  input: AccountCreateRequest,
): Promise<ActionResult<AccountView>> {
  try {
    const account = await adminApi.createPersonalAccount(input);
    revalidatePath("/personal-finance");
    return { ok: true, data: account };
  } catch (err) {
    return fromError(err, "Could not create the account.");
  }
}

export async function createTransactionAction(
  input: TransactionCreateRequest,
): Promise<ActionResult<TransactionView>> {
  try {
    const txn = await adminApi.createPersonalTransaction(input);
    revalidatePath("/personal-finance");
    return { ok: true, data: txn };
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 404) {
      return { ok: false, status: 404, message: "That account was not found for this tenant." };
    }
    return fromError(err, "Could not record the transaction.");
  }
}

export async function createBudgetAction(
  input: BudgetCreateRequest,
): Promise<ActionResult<BudgetView>> {
  try {
    const budget = await adminApi.createPersonalBudget(input);
    revalidatePath("/personal-finance");
    return { ok: true, data: budget };
  } catch (err) {
    return fromError(err, "Could not create the budget.");
  }
}
