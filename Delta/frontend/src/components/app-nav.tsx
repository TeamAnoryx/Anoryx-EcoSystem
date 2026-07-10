"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS: Array<[string, string]> = [
  ["Dashboards", "/dashboards"],
  ["Chargeback", "/chargeback"],
  ["CRM", "/crm"],
  ["ERP", "/erp"],
  ["Invoicing", "/invoicing"],
  ["Integrations", "/integrations"],
  ["PM", "/pm"],
  ["Capacity", "/capacity"],
  ["Access", "/rbac"],
  ["Allocations", "/allocations"],
  ["History", "/history"],
];

export function AppNav() {
  const path = usePathname();
  const isActive = (href: string) => path === href || path.startsWith(`${href}/`);

  const linkClass = (href: string) =>
    `rounded-md px-2 py-1 text-sm ${
      isActive(href) ? "bg-bg-inset font-medium text-fg" : "text-fg-muted hover:text-fg"
    }`;

  return (
    <nav aria-label="Primary" className="flex flex-wrap items-center gap-1">
      {LINKS.map(([label, href]) => (
        <Link key={href} href={href} aria-current={isActive(href) ? "page" : undefined} className={linkClass(href)}>
          {label}
        </Link>
      ))}
    </nav>
  );
}
