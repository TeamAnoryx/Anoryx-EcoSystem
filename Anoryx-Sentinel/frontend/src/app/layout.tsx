import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: "Sentinel Admin Console",
  description: "Anoryx Sentinel operator console",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-full">{children}</body>
    </html>
  );
}
