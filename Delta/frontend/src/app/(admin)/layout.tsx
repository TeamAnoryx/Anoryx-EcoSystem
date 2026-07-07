import { redirect } from "next/navigation";

import { AppNav } from "@/components/app-nav";
import { LogoutButton } from "@/components/logout-button";
import { getSession } from "@/lib/session";

// Every admin route is request-time dynamic (reads the session cookie); never
// statically prerendered (so the build needs no secrets).
export const dynamic = "force-dynamic";

/**
 * Fail-closed server guard for the entire admin route group. This is the
 * AUTHORITATIVE session check (full HMAC verification via `getSession()`,
 * Node runtime) — src/middleware.ts only does a cheap Edge-safe cookie-
 * presence redirect ahead of this. No valid session -> redirect to /login
 * BEFORE any admin data renders.
 */
export default function AdminLayout({ children }: { children: React.ReactNode }) {
  if (!getSession()) {
    redirect("/login");
  }

  return (
    <div className="min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded-md focus:bg-accent focus:px-3 focus:py-2 focus:text-sm focus:text-accent-fg"
      >
        Skip to content
      </a>
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border bg-bg-raised px-6 py-3">
        <div className="flex items-center gap-4">
          <span className="font-mono text-sm font-semibold text-fg">Delta Admin</span>
          <AppNav />
        </div>
        <LogoutButton />
      </header>
      <main id="main" className="mx-auto max-w-6xl px-6 py-8">
        {children}
      </main>
    </div>
  );
}
