"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function TenantTabs({ tenantId }: { tenantId: string }) {
  const base = `/tenants/${tenantId}`;
  const tabs: Array<[string, string]> = [
    ["Overview", base],
    ["Keys", `${base}/keys`],
    ["Policies", `${base}/policies`],
    ["Config", `${base}/config`],
    ["Audit", `${base}/audit`],
    ["RBAC", `${base}/rbac`],
  ];
  const path = usePathname();

  return (
    <nav aria-label="Tenant sections" className="flex flex-wrap gap-1 border-b border-border">
      {tabs.map(([label, href]) => {
        const active = path === href;
        return (
          <Link
            key={href}
            href={href}
            aria-current={active ? "page" : undefined}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${
              active
                ? "border-accent font-medium text-fg"
                : "border-transparent text-fg-muted hover:text-fg"
            }`}
          >
            {label}
          </Link>
        );
      })}
    </nav>
  );
}
