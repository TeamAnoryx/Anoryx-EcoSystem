"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

/**
 * Operator login form (ADR-0015 D1, Fork A). The token is POSTed to the server
 * route which compares it to SENTINEL_ADMIN_TOKEN server-side and sets the
 * session cookie. The token is never stored client-side — local state only for
 * the submit, then discarded.
 */
export function LoginForm() {
  const router = useRouter();
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: React.FormEvent) {
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

  return (
    <form onSubmit={onSubmit} className="mt-6 space-y-4" noValidate>
      <div>
        <label htmlFor="token" className="block text-sm font-medium text-fg">
          Admin token
        </label>
        <input
          id="token"
          name="token"
          type="password"
          autoComplete="off"
          autoFocus
          required
          value={token}
          onChange={(e) => setToken(e.target.value)}
          aria-invalid={error ? "true" : undefined}
          aria-describedby={error ? "login-error" : undefined}
          className="mt-1 w-full rounded-md border border-border bg-bg-inset px-3 py-2 font-mono text-sm text-fg placeholder:text-fg-faint"
          placeholder="paste operator token"
        />
      </div>

      {error ? (
        <p id="login-error" role="alert" className="text-sm text-danger">
          {error}
        </p>
      ) : null}

      <button
        type="submit"
        disabled={submitting || token.length === 0}
        className="w-full rounded-md bg-accent px-3 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50"
      >
        {submitting ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
