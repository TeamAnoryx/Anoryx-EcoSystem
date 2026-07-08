import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "Delta Admin Console",
  description: "Anoryx Delta budget-allocation admin console",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-full">{children}</body>
    </html>
  );
}
