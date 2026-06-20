import Link from "next/link";

import { adminApi } from "@/lib/admin-client";
import { toFriendlyError } from "@/lib/errors";

/**
 * Console home. Calls /admin/whoami through the server-only client to prove the
 * BFF token injection works end-to-end (vector 5). A gateway error renders a
 * friendly message, never a stack (vector 9).
 */
export default async function HomePage() {
  let principal: string | null = null;
  let error: string | null = null;
  try {
    principal = (await adminApi.whoami()).principal;
  } catch (e) {
    error = toFriendlyError(e).message;
  }

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-fg">Operator console</h1>
        <p className="mt-1 text-sm text-fg-muted">
          Manage tenants, virtual keys, policies, configuration, and the audit log.
        </p>
      </div>

      <div className="rounded-lg border border-border bg-bg-raised p-4">
        <h2 className="text-sm font-medium text-fg-muted">Gateway status</h2>
        {error ? (
          <p className="mt-2 text-sm text-danger" role="alert">
            {error}
          </p>
        ) : (
          <p className="mt-2 text-sm text-fg">
            Connected · principal <span className="font-mono text-accent">{principal}</span>
          </p>
        )}
      </div>

      <nav aria-label="Sections">
        <Link
          href="/tenants"
          className="inline-block rounded-md bg-accent px-4 py-2 text-sm font-semibold text-accent-fg"
        >
          Manage tenants →
        </Link>
      </nav>
    </section>
  );
}
