import { CreateInvoiceForm } from "@/components/invoicing/create-invoice-form";
import { InvoiceDecisionButtons } from "@/components/invoicing/invoice-decision-buttons";
import { RecordPaymentForm } from "@/components/invoicing/record-payment-form";
import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";
import { formatMinorUnits } from "@/lib/money";
import type { VendorView } from "@/lib/types";

export const dynamic = "force-dynamic";

interface Search {
  tenant_id?: string;
  vendor_id?: string;
}

export default function InvoicingPage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();
  const reconciliationVendorId = searchParams.vendor_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Invoicing</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Automated invoicing + vendor payment reconciliation — a three-way match: a
          D-014 approved purchase order, a submitted invoice (optionally proven by a
          D-015 task&apos;s &apos;done&apos; status as the delivery-metric leg), and
          recorded payments. This does not sync against an external ERP or bank feed
          (that&apos;s a future task) — reconciliation here is entirely internal to
          Delta&apos;s own procurement and billing records. An invoice decision and a
          recorded payment are both recorded in Delta&apos;s D-009 hash-chained audit
          log.
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
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to view its invoices.</p>
      ) : (
        <InvoicingForTenant tenantId={tenantId} reconciliationVendorId={reconciliationVendorId} />
      )}
    </div>
  );
}

async function InvoicingForTenant({
  tenantId,
  reconciliationVendorId,
}: {
  tenantId: string;
  reconciliationVendorId?: string;
}) {
  let vendors, invoices, approvedPurchaseOrders;
  let loadError: string | null = null;
  try {
    [vendors, invoices, approvedPurchaseOrders] = await Promise.all([
      adminApi.listVendors(tenantId),
      adminApi.listInvoices(tenantId),
      adminApi.listPurchaseOrders(tenantId, "approved"),
    ]);
  } catch (err) {
    loadError =
      err instanceof AdminApiError
        ? toFriendlyError(err).message
        : "Could not load invoicing data.";
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
        <h2 className="text-sm font-medium text-fg">Invoices</h2>
        {invoices!.length === 0 ? (
          <p className="text-sm text-fg-faint">No invoices yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-fg-muted">
                <tr>
                  <th className="py-1 pr-4 font-medium">Invoice #</th>
                  <th className="py-1 pr-4 font-medium">Description</th>
                  <th className="py-1 pr-4 font-medium">Amount</th>
                  <th className="py-1 pr-4 font-medium">Paid</th>
                  <th className="py-1 pr-4 font-medium">Status</th>
                  <th className="py-1 font-medium">Action</th>
                </tr>
              </thead>
              <tbody>
                {invoices!.map((inv) => (
                  <tr key={inv.invoice_id} className="border-t border-border">
                    <td className="py-1.5 pr-4 font-mono text-xs text-fg">{inv.invoice_number}</td>
                    <td className="py-1.5 pr-4 text-fg">{inv.description}</td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {formatMinorUnits(inv.amount_minor_units, inv.currency)}
                    </td>
                    <td className="py-1.5 pr-4 tabular-nums text-fg-muted">
                      {formatMinorUnits(inv.amount_paid_minor_units, inv.currency)}
                    </td>
                    <td className="py-1.5 pr-4 text-fg-muted">{inv.status}</td>
                    <td className="py-1.5">
                      {inv.status === "submitted" ? (
                        <InvoiceDecisionButtons invoiceId={inv.invoice_id} tenantId={tenantId} />
                      ) : inv.status === "approved" || inv.status === "partially_paid" ? (
                        <RecordPaymentForm invoiceId={inv.invoice_id} tenantId={tenantId} />
                      ) : (
                        <span className="text-xs text-fg-faint">
                          {inv.status === "disputed"
                            ? `disputed by ${inv.decided_by}`
                            : "fully paid"}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <CreateInvoiceForm
          tenantId={tenantId}
          vendors={vendors!}
          approvedPurchaseOrders={approvedPurchaseOrders!}
        />
      </section>

      <ReconciliationSection
        tenantId={tenantId}
        vendors={vendors!}
        selectedVendorId={reconciliationVendorId}
      />
    </div>
  );
}

async function ReconciliationSection({
  tenantId,
  vendors,
  selectedVendorId,
}: {
  tenantId: string;
  vendors: VendorView[];
  selectedVendorId?: string;
}) {
  return (
    <section className="space-y-3 rounded-lg border border-border bg-bg-raised p-4">
      <h2 className="text-sm font-medium text-fg">Vendor reconciliation</h2>
      <p className="text-xs text-fg-muted">
        Committed (approved PO totals) vs. invoiced (non-disputed invoices) vs. paid,
        per vendor. The <code>over_invoiced</code>/<code>over_paid</code> flags are
        defense-in-depth checks — the create/pay guards already make both structurally
        impossible, so a flagged row would mean those guards were bypassed.
      </p>
      <form method="GET" className="flex flex-wrap items-end gap-3">
        <input type="hidden" name="tenant_id" value={tenantId} />
        <div className="min-w-[16rem]">
          <label htmlFor="vendor_id" className="block text-sm font-medium text-fg">
            Vendor
          </label>
          <select
            id="vendor_id"
            name="vendor_id"
            defaultValue={selectedVendorId ?? ""}
            className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 text-sm text-fg"
          >
            <option value="">Select a vendor…</option>
            {vendors.map((v) => (
              <option key={v.vendor_id} value={v.vendor_id}>
                {v.name}
              </option>
            ))}
          </select>
        </div>
        <button
          type="submit"
          className="rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg"
        >
          Reconcile
        </button>
      </form>
      {selectedVendorId ? <ReconciliationReport tenantId={tenantId} vendorId={selectedVendorId} /> : null}
    </section>
  );
}

async function ReconciliationReport({
  tenantId,
  vendorId,
}: {
  tenantId: string;
  vendorId: string;
}) {
  let report;
  try {
    report = await adminApi.getVendorReconciliation(tenantId, vendorId);
  } catch (err) {
    const message =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load reconciliation.";
    return (
      <p role="alert" className="text-sm text-danger">
        {message}
      </p>
    );
  }

  return (
    <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
      <div className="rounded-md border border-border bg-bg-inset p-3">
        <dt className="text-xs text-fg-muted">Committed</dt>
        <dd className="tabular-nums text-fg">
          {formatMinorUnits(report.committed_minor_units, report.currency)}
        </dd>
      </div>
      <div className="rounded-md border border-border bg-bg-inset p-3">
        <dt className="text-xs text-fg-muted">Invoiced</dt>
        <dd className="tabular-nums text-fg">
          {formatMinorUnits(report.invoiced_minor_units, report.currency)}
        </dd>
      </div>
      <div className="rounded-md border border-border bg-bg-inset p-3">
        <dt className="text-xs text-fg-muted">Paid</dt>
        <dd className="tabular-nums text-fg">
          {formatMinorUnits(report.paid_minor_units, report.currency)}
        </dd>
      </div>
      <div className="rounded-md border border-border bg-bg-inset p-3">
        <dt className="text-xs text-fg-muted">Outstanding</dt>
        <dd className="tabular-nums text-fg">
          {formatMinorUnits(report.outstanding_minor_units, report.currency)}
        </dd>
      </div>
      {report.disputed_invoice_count > 0 ? (
        <p className="col-span-2 text-xs text-fg-muted sm:col-span-4">
          {report.disputed_invoice_count} disputed invoice(s) excluded from the invoiced total.
        </p>
      ) : null}
      {report.over_invoiced || report.over_paid ? (
        <p role="alert" className="col-span-2 text-xs text-danger sm:col-span-4">
          Reconciliation mismatch detected — this should be structurally impossible; investigate.
        </p>
      ) : null}
    </dl>
  );
}
