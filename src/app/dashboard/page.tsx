import Link from "next/link";
import type { Metadata } from "next";
import { desc, sql } from "drizzle-orm";
import { ChevronRight, Crosshair, Ghost, History, Trophy } from "lucide-react";
import { db } from "@/db";
import { scans } from "@/db/schema";
import { CountsBar, gradeColor, LegalNote } from "@/components/ui";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Scan History — BountyHawk" };

export default async function DashboardPage() {
  let rows: Awaited<ReturnType<typeof loadScans>> = [];
  let totals = { n: 0, findings: 0, points: 0 };
  try {
    rows = await loadScans();
    const agg = await db
      .select({
        n: sql<number>`count(*)::int`,
        findings: sql<number>`coalesce(sum(${scans.findingsCount}),0)::int`,
        points: sql<number>`coalesce(sum(${scans.totalPoints}),0)::int`,
      })
      .from(scans);
    totals = agg[0] ?? totals;
  } catch {
    /* DB not ready yet */
  }

  return (
    <div className="mx-auto max-w-6xl px-4 py-10">
      <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 font-mono-term text-2xl font-black text-slate-100">
            <History className="h-6 w-6 text-emerald-400" />
            scan_history
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            {totals.n} targets hunted · {totals.findings} bugs logged ·{" "}
            <span className="text-emerald-400">{totals.points.toLocaleString()} bounty points</span>
          </p>
        </div>
        <Link
          href="/"
          className="flex items-center gap-2 rounded-lg border border-emerald-400/50 bg-emerald-400/10 px-4 py-2 font-mono-term text-xs font-bold text-emerald-300 transition hover:bg-emerald-400/20 box-glow"
        >
          <Crosshair className="h-4 w-4" />
          new_scan
        </Link>
      </div>

      {rows.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-700 bg-slate-900/30 px-6 py-20 text-center">
          <Ghost className="mx-auto h-10 w-10 text-slate-600" />
          <p className="mt-4 font-mono-term text-sm text-slate-400">
            $ no scans found in database
          </p>
          <p className="mt-2 text-sm text-slate-500">
            Pehla hunt start karo — homepage par ek URL drop karo.
          </p>
          <Link
            href="/"
            className="mt-6 inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-5 py-2.5 font-mono-term text-sm font-black text-gray-950 hover:bg-emerald-400"
          >
            <Trophy className="h-4 w-4" /> START HUNTING
          </Link>
        </div>
      ) : (
        <div className="space-y-3">
          {rows.map((r) => (
            <Link
              key={r.id}
              href={`/scan/${r.id}`}
              className="group block rounded-xl border border-slate-800/80 bg-slate-900/40 p-4 transition hover:border-emerald-500/40 hover:bg-slate-900/70 sm:p-5"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex min-w-0 items-center gap-4">
                  <div
                    className={`grid h-12 w-12 shrink-0 place-items-center rounded-lg border border-slate-700 bg-gray-950 font-mono-term text-xl font-black ${gradeColor(
                      r.status === "completed" ? r.grade : null
                    )}`}
                  >
                    {r.status === "completed" ? r.grade ?? "?" : "✕"}
                  </div>
                  <div className="min-w-0">
                    <p className="truncate font-mono-term text-base font-bold text-slate-100 group-hover:text-emerald-300">
                      {r.host}
                    </p>
                    <p className="mt-0.5 truncate font-mono-term text-[11px] text-slate-500">
                      #{r.id} · {new Date(r.createdAt).toLocaleString()} ·{" "}
                      {r.statusCode ? `HTTP ${r.statusCode}` : r.status === "failed" ? "unreachable" : ""}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  {r.status === "completed" && (
                    <div className="hidden md:block">
                      <CountsBar counts={r.counts ?? undefined} />
                    </div>
                  )}
                  <div className="text-right">
                    {r.status === "completed" ? (
                      <>
                        <p className="font-mono-term text-lg font-black text-emerald-400">
                          +{r.totalPoints.toLocaleString()}
                        </p>
                        <p className="font-mono-term text-[10px] uppercase tracking-widest text-slate-500">
                          pts · {r.findingsCount} bugs
                        </p>
                      </>
                    ) : (
                      <span className="rounded border border-rose-500/40 bg-rose-500/10 px-2 py-1 font-mono-term text-[10px] font-bold uppercase tracking-widest text-rose-300">
                        scan failed
                      </span>
                    )}
                    <ChevronRight className="ml-auto mt-1 h-4 w-4 text-slate-600 transition group-hover:translate-x-1 group-hover:text-emerald-400" />
                  </div>
                </div>
              </div>

              {r.status === "completed" && Array.isArray(r.tech) && r.tech.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1.5 border-t border-slate-800/70 pt-3">
                  {r.tech.slice(0, 10).map((t) => (
                    <span
                      key={t}
                      className="rounded border border-slate-700/70 bg-slate-800/50 px-2 py-0.5 font-mono-term text-[10px] text-slate-400"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              )}
              {r.status === "failed" && r.error && (
                <p className="mt-3 border-t border-slate-800/70 pt-3 font-mono-term text-[11px] text-rose-300/80">
                  ↳ {r.error}
                </p>
              )}
            </Link>
          ))}
        </div>
      )}

      <div className="pt-12">
        <LegalNote />
      </div>
    </div>
  );
}

async function loadScans() {
  return db.select().from(scans).orderBy(desc(scans.createdAt)).limit(40);
}
