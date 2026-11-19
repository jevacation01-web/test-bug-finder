import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import Nav from "@/components/nav";

export const metadata: Metadata = {
  title: "BountyHawk — Web Vulnerability Scanner & Bug Bounty Recon",
  description:
    "Paste a target URL, run a full passive security scan, uncover misconfigurations, and read exploit-style PoCs with remediation for every finding.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-950 text-slate-200 antialiased">
        <Nav />
        <main>{children}</main>
      </body>
    </html>
  );
}
