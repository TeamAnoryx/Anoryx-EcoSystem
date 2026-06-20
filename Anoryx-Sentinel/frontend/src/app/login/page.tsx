import { LoginForm } from "@/components/login-form";

// Dynamic render so the middleware per-request CSP nonce is applied to the
// framework scripts (a statically prerendered page cannot carry a per-request
// nonce — security-audit M1).
export const dynamic = "force-dynamic";

export default function LoginPage() {
  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm rounded-lg border border-border bg-bg-raised p-6 shadow-lg">
        <h1 className="font-mono text-lg font-semibold text-fg">Sentinel Admin</h1>
        <p className="mt-1 text-sm text-fg-muted">Operator sign-in</p>
        <LoginForm />
        <p className="mt-4 text-xs text-fg-faint">
          The token is verified server-side and never stored in your browser.
        </p>
      </div>
    </main>
  );
}
