import Link from "next/link";
import { notFound } from "next/navigation";

import { AddDealForm } from "@/components/crm/add-deal-form";
import { AddInteractionForm } from "@/components/crm/add-interaction-form";
import { AddStakeholderForm } from "@/components/crm/add-stakeholder-form";
import { DealStageControl } from "@/components/crm/deal-stage-control";
import { StatTile } from "@/components/dashboards/stat-tile";
import { adminApi } from "@/lib/admin-client";
import { AdminApiError } from "@/lib/errors";
import { formatMinorUnits } from "@/lib/money";

export const dynamic = "force-dynamic";

export default async function ClientDetailPage({
  params,
  searchParams,
}: {
  params: { clientId: string };
  searchParams: { tenant_id?: string };
}) {
  const tenantId = searchParams.tenant_id?.trim();

  if (!tenantId) {
    return (
      <div className="space-y-3">
        <h1 className="font-mono text-lg font-semibold text-fg">Client</h1>
        <p role="alert" className="text-sm text-danger">
          A <code>?tenant_id=</code> query parameter is required to look up this client.
        </p>
        <Link href="/crm" className="text-sm text-accent hover:underline">
          Back to CRM
        </Link>
      </div>
    );
  }

  let detail;
  try {
    detail = await adminApi.getClientDetail(tenantId, params.clientId);
  } catch (err) {
    if (err instanceof AdminApiError && err.status === 404) {
      notFound();
    }
    throw err;
  }

  const { client, deals, recent_interactions: interactions, stakeholders, relationship_score } =
    detail;

  return (
    <div className="space-y-6">
      <div>
        <Link
          href={`/crm?tenant_id=${encodeURIComponent(tenantId)}`}
          className="text-sm text-accent hover:underline"
        >
          ← Back to CRM
        </Link>
        <h1 className="mt-2 font-mono text-lg font-semibold text-fg">{client.name}</h1>
        <p className="mt-1 text-sm text-fg-muted">
          {client.primary_contact_name ?? "—"}
          {client.primary_contact_email ? ` · ${client.primary_contact_email}` : ""}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatTile
          label="Relationship score"
          value={relationship_score.score.toFixed(0)}
          hint={`method: ${relationship_score.method}`}
        />
        <StatTile label="Open deals" value={String(relationship_score.open_deal_count)} />
        <StatTile
          label="Interactions (90d)"
          value={String(relationship_score.interaction_count_90d)}
        />
        <StatTile
          label="Last contact"
          value={
            relationship_score.days_since_last_interaction === null
              ? "never"
              : `${relationship_score.days_since_last_interaction}d ago`
          }
        />
      </div>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Deal pipeline</h2>
        {deals.length === 0 ? (
          <p className="text-sm text-fg-faint">No deals yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Name</th>
                  <th className="py-1 pr-4 font-medium">Stage</th>
                  <th className="py-1 pr-4 font-medium">Value</th>
                  <th className="py-1 font-medium">Transition</th>
                </tr>
              </thead>
              <tbody>
                {deals.map((d) => (
                  <tr key={d.deal_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{d.name}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{d.stage}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {d.value_minor_units === null || d.currency === null
                        ? "—"
                        : formatMinorUnits(d.value_minor_units, d.currency)}
                    </td>
                    <td className="py-1.5">
                      <DealStageControl
                        clientId={client.client_id}
                        dealId={d.deal_id}
                        tenantId={tenantId}
                        currentStage={d.stage}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <AddDealForm clientId={client.client_id} tenantId={tenantId} />
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">
          Stakeholders <span className="font-normal text-fg-faint">(engagement computed live)</span>
        </h2>
        {stakeholders.length === 0 ? (
          <p className="text-sm text-fg-faint">No stakeholders yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Name</th>
                  <th className="py-1 pr-4 font-medium">Role</th>
                  <th className="py-1 pr-4 font-medium">Interactions</th>
                  <th className="py-1 font-medium">Last contact</th>
                </tr>
              </thead>
              <tbody>
                {stakeholders.map((s) => (
                  <tr key={s.stakeholder_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{s.name}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{s.role}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {s.interaction_count}
                    </td>
                    <td className="py-1.5 tabular-nums text-fg-muted">
                      {s.last_interaction_at ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <AddStakeholderForm clientId={client.client_id} tenantId={tenantId} />
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Recent interactions</h2>
        {interactions.length === 0 ? (
          <p className="text-sm text-fg-faint">No interactions logged yet.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {interactions.map((i) => (
              <li key={i.interaction_id} className="border-t border-border pt-2 first:border-t-0 first:pt-0">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="rounded-full bg-bg-inset px-2 py-0.5 text-xs text-fg-muted">
                    {i.interaction_type}
                  </span>
                  <span className="text-xs text-fg-faint">{i.occurred_at}</span>
                  <span className="text-xs text-fg-faint">by {i.created_by}</span>
                </div>
                <p className="mt-1 text-fg">{i.summary}</p>
              </li>
            ))}
          </ul>
        )}
        <AddInteractionForm
          clientId={client.client_id}
          tenantId={tenantId}
          stakeholders={stakeholders}
        />
      </section>
    </div>
  );
}
