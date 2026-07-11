"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { createTransactionAction } from "@/app/(admin)/personal-finance/actions";
import type { AccountView, PersonalTransactionCategory } from "@/lib/types";

const CATEGORIES: PersonalTransactionCategory[] = [
  "groceries",
  "rent",
  "utilities",
  "dining",
  "transport",
  "entertainment",
  "subscriptions",
  "healthcare",
  "income",
  "transfer",
  "other",
];

export function CreateTransactionForm({
  tenantId,
  accounts,
}: {
  tenantId: string;
  accounts: AccountView[];
}) {
  const router = useRouter();
  const [accountId, setAccountId] = useState(accounts[0]?.account_id ?? "");
  const [category, setCategory] = useState<PersonalTransactionCategory>("groceries");
  const [amountDollars, setAmountDollars] = useState("");
  const [isExpense, setIsExpense] = useState(true);
  const [merchant, setMerchant] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // `accounts` arrives as a prop from a server re-fetch — the `useState` initializer
  // only runs once at mount, so it goes stale the moment the list changes underneath
  // it (mirrors invoicing/create-invoice-form.tsx's identical fix).
  useEffect(() => {
    if (!accounts.some((a) => a.account_id === accountId)) {
      setAccountId(accounts[0]?.account_id ?? "");
    }
  }, [accounts, accountId]);

  async function submit() {
    setError(null);
    if (!accountId) {
      setError("Add an account first.");
      return;
    }
    const magnitude = Math.round(Number(amountDollars) * 100);
    if (!Number.isFinite(magnitude) || magnitude <= 0) {
      setError("Amount must be a positive number.");
      return;
    }
    setBusy(true);
    const result = await createTransactionAction({
      tenant_id: tenantId,
      account_id: accountId,
      category,
      amount_minor_units: isExpense ? -magnitude : magnitude,
      currency: "USD",
      merchant: merchant.trim() || null,
      occurred_at: new Date().toISOString(),
    });
    setBusy(false);
    if (!result.ok) {
      setError(result.message);
      return;
    }
    setAmountDollars("");
    setMerchant("");
    router.refresh();
  }

  return (
    <div className="space-y-2 rounded-md border border-border bg-bg-inset p-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-5">
        <select
          value={accountId}
          onChange={(e) => setAccountId(e.target.value)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {accounts.length === 0 ? <option value="">No accounts yet</option> : null}
          {accounts.map((a) => (
            <option key={a.account_id} value={a.account_id}>
              {a.name}
            </option>
          ))}
        </select>
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value as PersonalTransactionCategory)}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <select
          value={isExpense ? "expense" : "income"}
          onChange={(e) => setIsExpense(e.target.value === "expense")}
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        >
          <option value="expense">Expense</option>
          <option value="income">Income</option>
        </select>
        <input
          type="text"
          inputMode="decimal"
          value={amountDollars}
          onChange={(e) => setAmountDollars(e.target.value)}
          placeholder="Amount, USD"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
        <input
          type="text"
          value={merchant}
          onChange={(e) => setMerchant(e.target.value)}
          placeholder="Merchant (optional)"
          className="rounded-md border border-border bg-bg-raised px-2 py-1.5 text-sm text-fg"
        />
      </div>
      <button
        type="button"
        onClick={submit}
        disabled={busy}
        className="rounded-md bg-accent px-3 py-1.5 text-sm font-semibold text-accent-fg disabled:opacity-50"
      >
        {busy ? "Recording…" : "Record transaction"}
      </button>
      {error ? (
        <p role="alert" className="text-xs text-danger">
          {error}
        </p>
      ) : null}
    </div>
  );
}
