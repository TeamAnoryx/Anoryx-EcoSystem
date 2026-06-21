"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

/**
 * Operator login form (ADR-0015 D1, Fork A; extended by ADR-0017 D8).
 *
 * Two sign-in paths:
 *   A. Break-glass — operator pastes the SENTINEL_ADMIN_TOKEN. POSTed to
 *      /api/login (server route); compared constant-time to the env secret;
 *      token is discarded from state immediately on success. Token never stored
 *      client-side.
 *   B. SSO — operator enters a tenant identifier and clicks "Sign in with SSO".
 *      The form POSTs to /api/sso/oidc/login (server route); on success the
 *      server returns {authorization_url} and the browser follows the redirect
 *      to the IdP. The IdP redirects back to /sso/oidc/callback (route handler)
 *      which calls Python, sets the httpOnly session cookie, and redirects to /.
 *      No IdP secret or operator-session token ever touches client JS (R6).
 */
export function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const errorParam = searchParams?.get("error");

  const [tab, setTab] = useState<"breakglass" | "sso">("sso");

  // Break-glass state
  const [token, setToken] = useState("");

  // SSO state
  const [tenantId, setTenantId] = useState("");

  const [error, setError] = useState<string | null>(errorParamToMessage(errorParam));
  const [submitting, setSubmitting] = useState(false);

  async function onBreakglassSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (res.ok) {
        setToken("");
        router.replace("/");
        router.refresh();
        return;
      }
      setError(res.status === 429 ? "Too many attempts. Wait and try again." : "Invalid admin token.");
    } catch {
      setError("Could not reach the server. Try again.");
    } finally {
      setSubmitting(false);
    }
  }

  async function onSsoSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await fetch("/api/sso/oidc/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant_id: tenantId.trim() }),
      });
      if (res.status === 429) {
        setError("Too many attempts. Wait and try again.");
        return;
      }
      if (!res.ok) {
        setError("SSO is not available for this tenant. Contact your administrator.");
        return;
      }
      const data = (await res.json()) as { authorization_url?: string };
      if (!data?.authorization_url) {
        setError("SSO configuration error. Contact your administrator.");
        return;
      }
      // Redirect the browser to the IdP — this leaves the console.
      window.location.href = data.authorization_url;
    } catch {
      setError("Could not reach the server. Try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mt-6">
      {/* Tab switcher */}
      <div role="tablist" aria-label="Sign-in method" className="flex border-b border-border">
        <button
          role="tab"
          aria-selected={tab === "sso"}
          aria-controls="panel-sso"
          id="tab-sso"
          onClick={() => { setTab("sso"); setError(null); }}
          className={`px-3 py-2 text-sm font-medium transition-colors ${
            tab === "sso"
              ? "border-b-2 border-accent text-fg"
              : "text-fg-muted hover:text-fg"
          }`}
        >
          SSO
        </button>
        <button
          role="tab"
          aria-selected={tab === "breakglass"}
          aria-controls="panel-breakglass"
          id="tab-breakglass"
          onClick={() => { setTab("breakglass"); setError(null); }}
          className={`px-3 py-2 text-sm font-medium transition-colors ${
            tab === "breakglass"
              ? "border-b-2 border-accent text-fg"
              : "text-fg-muted hover:text-fg"
          }`}
        >
          Break-glass
        </button>
      </div>

      {/* SSO panel */}
      <div
        id="panel-sso"
        role="tabpanel"
        aria-labelledby="tab-sso"
        hidden={tab !== "sso"}
      >
        <form onSubmit={onSsoSubmit} className="mt-5 space-y-4" noValidate>
          <div>
            <label htmlFor="tenant-id" className="block text-sm font-medium text-fg">
              Tenant identifier
            </label>
            <input
              id="tenant-id"
              name="tenant_id"
              type="text"
              autoComplete="organization"
              required
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              aria-invalid={error ? "true" : undefined}
              aria-describedby={error ? "login-error" : undefined}
              className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg placeholder:text-fg-faint"
              placeholder="your-tenant-id"
            />
          </div>

          {error && tab === "sso" ? (
            <p id="login-error" role="alert" className="text-sm text-danger">
              {error}
            </p>
          ) : null}

          <button
            type="submit"
            disabled={submitting || tenantId.trim().length === 0}
            className="w-full rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50"
          >
            {submitting ? "Redirecting to IdP…" : "Sign in with SSO"}
          </button>
        </form>
      </div>

      {/* Break-glass panel */}
      <div
        id="panel-breakglass"
        role="tabpanel"
        aria-labelledby="tab-breakglass"
        hidden={tab !== "breakglass"}
      >
        <form onSubmit={onBreakglassSubmit} className="mt-5 space-y-4" noValidate>
          <div>
            <label htmlFor="token" className="block text-sm font-medium text-fg">
              Admin token
            </label>
            <input
              id="token"
              name="token"
              type="password"
              autoComplete="off"
              required
              value={token}
              onChange={(e) => setToken(e.target.value)}
              aria-invalid={error ? "true" : undefined}
              aria-describedby={error ? "login-error-bg" : undefined}
              className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg placeholder:text-fg-faint"
              placeholder="paste operator token"
            />
          </div>

          {error && tab === "breakglass" ? (
            <p id="login-error-bg" role="alert" className="text-sm text-danger">
              {error}
            </p>
          ) : null}

          <button
            type="submit"
            disabled={submitting || token.length === 0}
            className="w-full rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50"
          >
            {submitting ? "Signing in…" : "Sign in (break-glass)"}
          </button>
        </form>
        <p className="mt-4 text-xs text-fg-faint">
          Break-glass: the token is verified server-side and never stored in your
          browser. Every break-glass authentication is audited.
        </p>
      </div>
    </div>
  );
}

function errorParamToMessage(error: string | null): string | null {
  if (!error) return null;
  switch (error) {
    case "no_role":
      return "Your account has no role assigned in this tenant. Contact your administrator.";
    case "sso_failed":
      return "SSO authentication failed. Try again or use break-glass.";
    default:
      return "Sign-in error. Try again.";
  }
}
