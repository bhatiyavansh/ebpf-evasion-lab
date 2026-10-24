import type { Metadata } from "next";
import "./globals.css";
import AppShell from "@/components/AppShell";

export const metadata: Metadata = {
  title: "Adaptive eBPF Security Lab",
  description:
    "Runtime observability and detection evaluation for Linux containers — Falco, Tracee and Tetragon under adaptive container behavior, plus a real-CVE compatibility lab.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="font-sans antialiased">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
