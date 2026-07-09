import { CreateTokenForm } from "@/components/rbac/create-token-form";
import { RevokeTokenButton } from "@/components/rbac/revoke-token-button";
import { adminApi } from "@/lib/admin-client";
import { AdminApiError, toFriendlyError } from "@/lib/errors";

export const dynamic = "force-dynamic";

interface Search {
  tenant_id?: string;
}

export default function RbacPage({ searchParams }: { searchParams: Search }) {
  const tenantId = searchParams.tenant_id?.trim();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-mono text-lg font-semibold text-fg">Access tokens</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Locally-issued, role-tagged bearer tokens (<code className="font-mono text-xs">tenant_admin</code>
          {" / "}
          <code className="font-mono text-xs">tenant_auditor</code>) gating the Dashboards page —
          not real SSO/OIDC/SAML (that&apos;s Anoryx-Sentinel&apos;s own F-014). The break-glass
          admin token keeps working everywhere it already does. See{" "}
          <code className="font-mono text-xs">docs/adr/0017-delta-rbac-dashboards.md</code>.
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
        <p className="text-sm text-fg-faint">Enter a tenant UUID above to manage its access tokens.</p>
      ) : (
        <TokensForTenant tenantId={tenantId} />
      )}
    </div>
  );
}

async function TokensForTenant({ tenantId }: { tenantId: string }) {
  let tokens;
  let loadError: string | null = null;
  try {
    tokens = await adminApi.listAccessTokens(tenantId);
  } catch (err) {
    loadError =
      err instanceof AdminApiError ? toFriendlyError(err).message : "Could not load access tokens.";
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
      <h2 className="text-sm font-medium text-fg">Tokens</h2>
      {tokens!.length === 0 ? (
        <p className="text-sm text-fg-faint">No tokens issued yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-fg-muted">
              <tr>
                <th className="py-1 pr-4 font-medium">Name</th>
                <th className="py-1 pr-4 font-medium">Role</th>
                <th className="py-1 pr-4 font-medium">Created</th>
                <th className="py-1 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {tokens!.map((t) => (
                <tr key={t.token_id} className="border-t border-border">
                  <td className="py-1.5 pr-4 text-fg">{t.name}</td>
                  <td className="py-1.5 pr-4 text-fg-muted">{t.role}</td>
                  <td className="py-1.5 pr-4 text-fg-muted">
                    {new Date(t.created_at).toLocaleString()}
                  </td>
                  <td className="py-1.5">
                    {t.revoked_at ? (
                      <span className="text-xs text-fg-faint">
                        revoked {new Date(t.revoked_at).toLocaleDateString()}
                      </span>
                    ) : (
                      <RevokeTokenButton tokenId={t.token_id} tenantId={tenantId} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <CreateTokenForm tenantId={tenantId} />
    </section>
  );
}
