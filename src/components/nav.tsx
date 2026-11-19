import Link from "next/link";
import { Bug, LayoutDashboard, Radar } from "lucide-react";

export default function Nav() {
  return (
    <header className="sticky top-0 z-50 border-b border-slate-800/70 bg-gray-950/80 backdrop-blur-md">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
        <Link href="/" className="group flex items-center gap-2.5">
          <span className="relative grid h-9 w-9 place-items-center rounded-lg border border-emerald-400/40 bg-emerald-400/10 box-glow">
            <Bug className="h-5 w-5 text-emerald-400" />
            <Radar className="absolute -bottom-1 -right-1 h-3.5 w-3.5 rounded-full bg-gray-950 p-px text-cyan-400" />
          </span>
          <span className="font-mono-term text-lg font-black tracking-tight text-slate-100">
            bounty<span className="text-emerald-400 text-glow">hawk</span>
            <span className="text-emerald-500 animate-pulse-dot">_</span>
          </span>
        </Link>
        <nav className="flex items-center gap-1 sm:gap-2">
          <Link
            href="/dashboard"
            className="flex items-center gap-1.5 rounded-lg border border-transparent px-3 py-1.5 font-mono-term text-xs font-semibold text-slate-400 transition hover:border-slate-700 hover:text-emerald-300"
          >
            <LayoutDashboard className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">scan_history</span>
            <span className="sm:hidden">history</span>
          </Link>
          <Link
            href="/"
            className="rounded-lg border border-emerald-400/50 bg-emerald-400/10 px-3 py-1.5 font-mono-term text-xs font-bold text-emerald-300 transition hover:bg-emerald-400/20 box-glow"
          >
            + new_scan
          </Link>
        </nav>
      </div>
    </header>
  );
}
