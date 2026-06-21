/** Shared "no tenant selected" notice for the dashboards (F-013). */
export function SelectTenantNotice() {
  return (
    <div className="rounded-lg border border-dashed border-border-strong bg-bg-raised p-6 text-sm text-fg-muted">
      Select a tenant above to load this dashboard. Each tenant is fetched in its own scoped
      request — switching tenants reloads the dashboard with only that tenant&apos;s data.
    </div>
  );
}
