import { LoginForm } from "@/components/login-form";

// Dynamic render: this page reads request-time state indirectly (redirect
// target) and must never be statically prerendered with secrets baked in.
export const dynamic = "force-dynamic";

export default function LoginPage() {
  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm rounded-lg border border-border bg-bg-raised p-6 shadow-lg">
        <h1 className="font-mono text-lg font-semibold text-fg">Delta Admin</h1>
        <p className="mt-1 text-sm text-fg-muted">Budget-allocation operator sign-in</p>
        <LoginForm />
      </div>
    </main>
  );
}
