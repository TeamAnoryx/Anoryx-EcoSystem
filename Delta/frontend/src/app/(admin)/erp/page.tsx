import { AssetStatusControl } from "@/components/erp/asset-status-control";
import { CreateAssetForm } from "@/components/erp/create-asset-form";
import { CreatePoForm } from "@/components/erp/create-po-form";
import { CreateVendorForm } from "@/components/erp/create-vendor-form";
import { PoDecisionButtons } from "@/components/erp/po-decision-buttons";
import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import { formatMinorUnits } from "@/lib/money";

export const dynamic = "force-dynamic";

interface Search {
  tenant_id?: string;
}

export default function ErpPage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">ERP</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Asset register + vendor/purchase-order procurement. A deliberately bounded slice —
          no payroll, no HR, no external real-time sync (that&apos;s a future task). A purchase-order
          decision is recorded in Delta&apos;s D-009 hash-chained audit log.
        </p>
      </div>

      <form
        method="GET"
        className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-bg-raised p-4"
      >
        <div className="min-w-[16rem] flex-1">
          <label htmlFor="tenant_id" className="block text-sm font-medium text-fg">
            Tenant UUID
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
        <button
          type="submit"
          className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg"
        >
          Load
        </button>
      </form>

      {!tenantId ? (
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view its ERP data.</p>
      ) : (
        <ErpForTenant tenantId={tenantId} />
      )}
    </div>
  );
}

async function ErpForTenant({ tenantId }: { tenantId: string }) {
  let vendors, assets, purchaseOrders;
  let loadError: string | null = null;
  try {
    [vendors, assets, purchaseOrders] = await Promise.all([
      adminApi.listVendors(tenantId),
      adminApi.listAssets(tenantId),
      adminApi.listPurchaseOrders(tenantId),
    ]);
  } catch (err) {
    loadError =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load ERP data.";
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
        <h2 className="text-sm font-medium text-fg">Vendors</h2>
        {vendors!.length === 0 ? (
          <p className="text-sm text-fg-faint">No vendors yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Name</th>
                  <th className="py-1 pr-4 font-medium">Contact</th>
                  <th className="py-1 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {vendors!.map((v) => (
                  <tr key={v.vendor_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{v.name}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{v.contact_email ?? "—"}</td>
                    <td className="py-1.5 text-fg-muted">{v.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <CreateVendorForm tenantId={tenantId} />
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Asset register</h2>
        {assets!.length === 0 ? (
          <p className="text-sm text-fg-faint">No assets yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Name</th>
                  <th className="py-1 pr-4 font-medium">Category</th>
                  <th className="py-1 pr-4 font-medium">Cost</th>
                  <th className="py-1 pr-4 font-medium">Status</th>
                  <th className="py-1 font-medium">Transition</th>
                </tr>
              </thead>
              <tbody>
                {assets!.map((a) => (
                  <tr key={a.asset_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{a.name}</td>
                    <td className="py-1.5 pr-4 text-fg-muted">{a.category}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {a.acquisition_cost_minor_units === null || a.currency === null
                        ? "—"
                        : formatMinorUnits(a.acquisition_cost_minor_units, a.currency)}
                    </td>
                    <td className="py-1.5 pr-4 text-fg-muted">{a.status}</td>
                    <td className="py-1.5">
                      <AssetStatusControl
                        assetId={a.asset_id}
                        tenantId={tenantId}
                        currentStatus={a.status}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <CreateAssetForm tenantId={tenantId} />
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg">Purchase orders</h2>
        {purchaseOrders!.length === 0 ? (
          <p className="text-sm text-fg-faint">No purchase orders yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Description</th>
                  <th className="py-1 pr-4 font-medium">Amount</th>
                  <th className="py-1 pr-4 font-medium">Status</th>
                  <th className="py-1 font-medium">Decision</th>
                </tr>
              </thead>
              <tbody>
                {purchaseOrders!.map((po) => (
                  <tr key={po.po_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 text-fg">{po.description}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {formatMinorUnits(po.amount_minor_units, po.currency)}
                    </td>
                    <td className="py-1.5 pr-4 text-fg-muted">{po.status}</td>
                    <td className="py-1.5">
                      {po.status === "requested" ? (
                        <PoDecisionButtons poId={po.po_id} tenantId={tenantId} />
                      ) : (
                        <span className="text-xs text-fg-faint">
                          {po.status} by {po.decided_by}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <CreatePoForm tenantId={tenantId} vendors={vendors!} assets={assets!} />
      </section>
    </div>
  );
}
