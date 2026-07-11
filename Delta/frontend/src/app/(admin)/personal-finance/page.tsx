import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import { formatMinorUnits, formatMinorUnitsCompact } from "@/lib/money";
import type { AccountView, FinancialHealthView, TransactionView } from "@/lib/types";

import { StatTile } from "@/components/dashboards/stat-tile";
import { CreateAccountForm } from "@/components/personal-finance/create-account-form";
import { CreateBudgetForm } from "@/components/personal-finance/create-budget-form";
import { CreateTransactionForm } from "@/components/personal-finance/create-transaction-form";

export const dynamic = "force-dynamic";

const PRESETS: Array<{ label: string; days: number }> = [
  { label: "Last 7d", days: 7 },
  { label: "Last 30d", days: 30 },
  { label: "Last 90d", days: 90 },
];

const DAY_MS = 24 * 3_600_000;

interface Search {
  tenant_id?: string;
  start?: string;
  end?: string;
}

function presetHref(tenantId: string, days: number): string {
  const end = new Date();
  const start = new Date(end.getTime() - days * DAY_MS);
  const qp = new URLSearchParams({
    tenant_id: tenantId,
    start: start.toISOString(),
    end: end.toISOString(),
  });
  return `/personal-finance?${qp.toString()}`;
}

export default function PersonalFinancePage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Personal Finance</h1>
        <p className="mt-1 text-sm text-fg-muted">
          B2C personal budget tracking (D-021). A B2C consumer is one tenant UUID here
          — there is no real signup/login flow yet (the &quot;B2C onboarding shell&quot;
          named as this track&apos;s dependency doesn&apos;t exist anywhere in this
          ecosystem; see ADR-0021 §3). This is an internal operator/testing console
          until that shell lands. The health score is a disclosed deterministic
          formula, not AI/ML.
        </p>
      </div>

      <form
        method="GET"
        className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-bg-raised p-4"
      >
        <div className="min-w-[16rem] flex-1">
          <label htmlFor="tenant_id" className="block text-sm font-medium text-fg">
            Tenant UUID (this consumer)
          </label>
          <input
            id="tenant_id"
            name="tenant_id"
            type="text"
            required
            defaultValue={tenantId ?? ""}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg"
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </div>
        <div>
          <label htmlFor="start" className="block text-sm font-medium text-fg">
            Start (UTC)
          </label>
          <input
            id="start"
            name="start"
            type="text"
            defaultValue={searchParams.start ?? ""}
            className="mt-1 w-56 rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-xs text-fg"
            placeholder="2026-07-01T00:00:00Z"
          />
        </div>
        <div>
          <label htmlFor="end" className="block text-sm font-medium text-fg">
            End (UTC)
          </label>
          <input
            id="end"
            name="end"
            type="text"
            defaultValue={searchParams.end ?? ""}
            className="mt-1 w-56 rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-xs text-fg"
            placeholder="2026-07-08T00:00:00Z"
          />
        </div>
        <button
          type="submit"
          className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg"
        >
          Load
        </button>
      </form>

      {tenantId ? (
        <div className="flex flex-wrap gap-2">
          {PRESETS.map((p) => (
            <a
              key={p.label}
              href={presetHref(tenantId, p.days)}
              className="rounded-md border border-border px-3 py-1.5 text-xs text-fg-muted hover:border-accent hover:text-fg"
            >
              {p.label}
            </a>
          ))}
        </div>
      ) : null}

      {!tenantId ? (
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view its finances.</p>
      ) : (
        <PersonalFinanceForTenant
          tenantId={tenantId}
          start={searchParams.start}
          end={searchParams.end}
        />
      )}
    </div>
  );
}

async function PersonalFinanceForTenant({
  tenantId,
  start,
  end,
}: {
  tenantId: string;
  start?: string;
  end?: string;
}) {
  let accounts: AccountView[];
  let transactions: TransactionView[];
  let loadError: string | null = null;
  try {
    [accounts, transactions] = await Promise.all([
      adminApi.listPersonalAccounts(tenantId),
      adminApi.listPersonalTransactions(tenantId, undefined, 50),
    ]);
  } catch (err) {
    loadError =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load accounts.";
    accounts = [];
    transactions = [];
  }

  if (loadError) {
    return (
      <p role="alert" className="text-sm text-danger">
        {loadError}
      </p>
    );
  }

  return (
    <div className="space-y-6">
      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Accounts</h2>
        {accounts.length === 0 ? (
          <p className="text-sm text-fg-faint">No accounts yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Name</th>
                  <th className="py-1 font-medium">Type</th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((a) => (
                  <tr key={a.account_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{a.name}</td>
                    <td className="py-1.5 text-fg-muted">{a.type}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <CreateAccountForm tenantId={tenantId} />
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Transactions</h2>
        {transactions.length === 0 ? (
          <p className="text-sm text-fg-faint">No transactions yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Date</th>
                  <th className="py-1 pr-4 font-medium">Category</th>
                  <th className="py-1 pr-4 font-medium">Merchant</th>
                  <th className="py-1 font-medium">Amount</th>
                </tr>
              </thead>
              <tbody>
                {transactions.map((t) => (
                  <tr key={t.txn_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg-muted">
                      {new Date(t.occurred_at).toLocaleDateString()}
                    </td>
                    <td className="py-1.5 pr-4 text-fg-muted">{t.category}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{t.merchant ?? "—"}</td>
                    <td
                      className={`py-1.5 tabular-nums ${t.amount_minor_units < 0 ? "text-danger" : "text-fg"}`}
                    >
                      {formatMinorUnits(t.amount_minor_units, t.currency)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <CreateTransactionForm tenantId={tenantId} accounts={accounts} />
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Budgets</h2>
        <CreateBudgetForm tenantId={tenantId} />
      </section>

      {!start || !end ? (
        <p className="text-sm text-fg-faint">
          Pick a window above (a preset, or type Start/End) to see the financial-health
          score.
        </p>
      ) : (
        <FinancialHealth tenantId={tenantId} start={start} end={end} />
      )}
    </div>
  );
}

async function FinancialHealth({
  tenantId,
  start,
  end,
}: {
  tenantId: string;
  start: string;
  end: string;
}) {
  let health: FinancialHealthView | null = null;
  let loadError: string | null = null;
  try {
    health = await adminApi.getFinancialHealth(tenantId, start, end);
  } catch (err) {
    loadError =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load health score.";
  }

  if (loadError) {
    return (
      <p role="alert" className="text-sm text-danger">
        {loadError}
      </p>
    );
  }

  return (
    <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
      <h2 className="text-sm font-medium text-fg">Financial health</h2>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatTile
          label="Health score"
          value={`${health!.health_score}/100`}
          hint="deterministic heuristic, not AI/ML — see ADR-0021 §2"
        />
        <StatTile
          label="Income"
          value={formatMinorUnitsCompact(health!.total_income_minor_units, health!.currency)}
        />
        <StatTile
          label="Expenses"
          value={formatMinorUnitsCompact(health!.total_expense_minor_units, health!.currency)}
        />
        <StatTile
          label="Savings rate"
          value={health!.savings_rate === null ? "—" : `${Math.round(health!.savings_rate * 100)}%`}
          hint={health!.savings_rate === null ? "no income recorded in window" : undefined}
        />
      </div>

      {health!.budgets.length === 0 ? (
        <p className="text-sm text-fg-faint">No budgets set yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-fg-muted">
              <tr>
                <th className="py-1 pr-4 font-medium">Category</th>
                <th className="py-1 pr-4 font-medium">Spent</th>
                <th className="py-1 pr-4 font-medium">Cap</th>
                <th className="py-1 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {health!.budgets.map((b) => (
                <tr key={b.category} className="border-t border-border">
                  <td className="py-1.5 pr-4 text-fg">{b.category}</td>
                  <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                    {formatMinorUnits(b.spent_minor_units, b.currency)}
                  </td>
                  <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                    {formatMinorUnits(b.cap_minor_units, b.currency)}
                  </td>
                  <td className={`py-1.5 ${b.over_cap ? "text-danger" : "text-fg-muted"}`}>
                    {b.over_cap ? "over cap" : "within cap"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
