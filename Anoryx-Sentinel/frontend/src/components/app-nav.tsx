"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const PRIMARY: Array<[string, string]> = [
  ["Home", "/"],
  ["Tenants", "/tenants"],
];

const DASHBOARDS: Array<[string, string]> = [
  ["Security", "/dashboards/security"],
  ["Compliance", "/dashboards/compliance"],
  ["Governance", "/dashboards/governance"],
];

export function AppNav() {
  const path = usePathname();
  const isActive = (href: string) => (href === "/" ? path === "/" : path.startsWith(href));

  const linkClass = (href: string) =>
    `rounded-md px-2 py-1 text-sm ${
      isActive(href) ? "bg-bg-inset font-medium text-fg" : "text-fg-muted hover:text-fg"
    }`;

  return (
    <nav aria-label="Primary" className="flex flex-wrap items-center gap-1">
      {PRIMARY.map(([label, href]) => (
        <Link key={href} href={href} aria-current={isActive(href) ? "page" : undefined} className={linkClass(href)}>
          {label}
        </Link>
      ))}
      <span className="mx-1 text-border-strong" aria-hidden="true">
        |
      </span>
      <span className="px-1 text-xs uppercase tracking-wide text-fg-faint">Dashboards</span>
      {DASHBOARDS.map(([label, href]) => (
        <Link key={href} href={href} aria-current={isActive(href) ? "page" : undefined} className={linkClass(href)}>
          {label}
        </Link>
      ))}
    </nav>
  );
}
